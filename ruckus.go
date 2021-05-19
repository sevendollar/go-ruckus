package goruckus

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"regexp"
	"strings"
)

type Ruckus struct {
	c   *http.Client
	err error

	baseURL string
	zoneId  string
	l2aclId string

	incorrectedMacs []string
	duplicatedMacs  []string
	correctedMacs   []string

	*RuckusError

	debug bool
}

func (rks *Ruckus) SetBaseUrl(address string, port interface{}) {
	// "https://<address>:<port>/wsg/api/public"
	intPort := 8443
	switch p := port.(type) {
	case int:
		if p < 1 || p > 65535 {
			intPort = p
		}
	case string, bool, nil:
	}

	rks.baseURL = fmt.Sprintf("https://%s:%d/wsg/api/public", address, intPort)
}

func NewRuckus() *Ruckus {
	// cookie jar
	jar, err := cookiejar.New(nil)
	if err != nil {
		log.Fatal(err)
	}

	// client
	client := &http.Client{
		Jar: jar,
	}

	return &Ruckus{
		c: client,
	}
}

func WithDebug() func(*Ruckus) {
	return func(rks *Ruckus) {
		rks.debug = true
	}
}

func (rks *Ruckus) Use(opts ...Options) {
	for _, opt := range opts {
		opt(rks)
	}
}

func (rks *Ruckus) SetZoneByName(name string) *Ruckus {
	if rks.Err() != nil {
		return rks
	}

	zoneName := name
	if zoneName == "" {
		rks.setErr(errors.New("name(zone) can not be empty"))
		return rks
	}

	zones, err := rks.GetZones()
	if err != nil {
		rks.setErr(err)
		return rks
	}

	zoneID := ""
	// zoneID, ok := zones[zoneName]
	// if !ok {
	// 	rks.err = fmt.Errorf("\"%s\"(zone) doesn't exist", zoneName)
	// 	return rks
	// }
	for _, zone := range zones {
		if strings.EqualFold(zone.Name, zoneName) {
			zoneID = zone.Id
		}
	}
	if zoneID == "" {
		rks.setErr(fmt.Errorf("\"%s\"(zone) doesn't exist", zoneName))
		return rks
	}

	rks.zoneId = zoneID
	rks.err = nil

	return rks
}

func (rks *Ruckus) SetL2aclByName(name string) *Ruckus {
	if rks.Err() != nil {
		return rks
	}

	aclName := name
	if aclName == "" {
		rks.err = errors.New("name(l2 ACL) can not be empty")
		return rks
	}

	acls, err := rks.GetL2aclList()
	if err != nil {
		rks.err = err
		return rks
	}

	for _, acl := range acls {
		if acl.Name == aclName {
			rks.l2aclId = acl.Id
			rks.err = nil

			return rks
		}
	}

	rks.setErr(fmt.Errorf("\"%s\"(L2 ACL) doesn't exist", aclName))
	return rks
}

func (rks *Ruckus) GetZoneId() string {
	return rks.zoneId
}

func (rks *Ruckus) GetL2aclId() string {
	return rks.l2aclId
}

func IsCorrectMac(mac string) bool {
	pattern := "^([0-9a-fA-F][0-9a-fA-F]:){5}([0-9a-fA-F][0-9a-fA-F])$"
	match, _ := regexp.MatchString(pattern, mac)
	return match
}

func IsDuplicatedMac(mac string, compareList []string) bool {
	for _, m := range compareList {
		if strings.EqualFold(strings.ToLower(m), strings.ToLower(mac)) {
			return true
		}
	}
	return false
}

func (rks *Ruckus) CheckMacsWithNoDuplitation(mac ...string) *Ruckus {
	if rks.Err() != nil {
		return rks
	}

	for _, m := range mac {
		if !IsCorrectMac(m) {
			rks.incorrectedMacs = append(rks.incorrectedMacs, m)
			continue
		}
		rks.correctedMacs = append(rks.correctedMacs, m)
	}

	return rks
}

func (rks *Ruckus) checkMacs(mac ...string) *Ruckus {
	if rks.Err() != nil {
		return rks
	}

	acl, err := rks.GetL2aclById(rks.GetL2aclId())
	if err != nil {
		rks.setErr(err)
		return rks
	}
	currentMacs := acl.RuleMacs

	for _, m := range mac {
		if !IsCorrectMac(m) {
			rks.incorrectedMacs = append(rks.incorrectedMacs, m)
			continue
		}
		if IsDuplicatedMac(m, currentMacs) {
			rks.duplicatedMacs = append(rks.duplicatedMacs, m)
			continue
		}
		rks.correctedMacs = append(rks.correctedMacs, m)
	}

	return rks
}

func (rks *Ruckus) GetDuplicatedMacs() []string {
	if rks.duplicatedMacs != nil {
		return rks.duplicatedMacs
	}
	return nil
}

func (rks *Ruckus) GetIncorrectMacs() []string {
	if rks.incorrectedMacs != nil {
		return rks.incorrectedMacs
	}
	return nil
}

func (rks *Ruckus) GetCorrectMacs() []string {
	if rks.correctedMacs != nil {
		return rks.correctedMacs
	}
	return nil
}

// L2 Access Control => DELETE
// Delete an L2 Access Control.
// response code should be 204
func (rks *Ruckus) DeleteL2aclByName(name string) error {
	if rks.Err() != nil {
		return rks.Err()
	}

	// check zone id existence
	if rks.GetZoneId() == "" {
		return rks.setErr(fmt.Errorf("run %s method first", setZoneByNameMethod))
	}

	// get acl id
	aclName := name
	aclId := ""
	if aclName == "" {
		return rks.setErr(fmt.Errorf("run %s method first", setL2aclByNameMethod))
	}
	acls, err := rks.GetL2aclList()
	if err != nil {
		return rks.setErr(err)
	}
	for _, acl := range acls {
		if aclName == acl.Name {
			aclId = acl.Id
			break
		}
	}

	// define the default response code
	const DefaultResponseCode = http.StatusNoContent

	// URL
	subURL := "/v6_1/rkszones/{zoneId}/l2ACL/{id}"
	url := rks.baseURL + strings.Replace(strings.Replace(subURL, "{zoneId}", rks.GetZoneId(), 1), "{id}", aclId, 1)

	// request
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return rks.setErr(err)
	}
	req.Header.Add("Content-Type", "application/json;charset=UTF-8")

	// send the request
	resp, err := rks.c.Do(req)
	if err != nil {
		return rks.setErr(err)
	}

	// read the response
	bj, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return rks.setErr(err)
	}
	// check JSON integrity
	checkJson(&bj)

	// trun JSON format to Go data format
	rksErr := RuckusError{}
	if err := json.Unmarshal(bj, &rksErr); err != nil {
		return rks.setErr(err)
	}

	// handel response errors
	if resp.StatusCode != DefaultResponseCode {
		if rks.RuckusError != nil && rks.ErrorCode != nil {
			rks.RuckusError = &rksErr
		}
		if rks.debug {
			log.Println("Http Status Code:", resp.StatusCode)
			log.Println("Http Status:", resp.Status)
			log.Println("Ruckus Error Code:", rks.GetErrorCode())
			log.Println("Ruckus Error Type:", rks.GetErrorType())
			log.Println("Ruckus Message:", rks.GetMessage())
		}
		return rks.setErr(errors.New(resp.Status))
	}

	return nil
}

// L2 Access Control => DELETE
// Delete an L2 Access Control.
// response code should be 204
func (rks *Ruckus) DeleteL2acl() error {
	if rks.Err() != nil {
		return rks.Err()
	}

	if rks.GetZoneId() == "" {
		return rks.setErr(fmt.Errorf("run %s method first", setZoneByNameMethod))
	}
	if rks.GetL2aclId() == "" {
		return rks.setErr(fmt.Errorf("run %s method first", setL2aclByNameMethod))
	}

	// define the default response code
	const DefaultResponseCode = http.StatusNoContent

	// URL
	subURL := "/v6_1/rkszones/{zoneId}/l2ACL/{id}"
	url := rks.baseURL + strings.Replace(strings.Replace(subURL, "{zoneId}", rks.GetZoneId(), 1), "{id}", rks.GetL2aclId(), 1)

	// request
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return rks.setErr(err)
	}
	req.Header.Add("Content-Type", "application/json;charset=UTF-8")

	// send the request
	resp, err := rks.c.Do(req)
	if err != nil {
		return rks.setErr(err)
	}

	// read the response
	bj, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return rks.setErr(err)
	}
	// check JSON integrity
	checkJson(&bj)

	// trun JSON format to Go data format
	rksErr := RuckusError{}
	if err := json.Unmarshal(bj, &rksErr); err != nil {
		return rks.setErr(err)
	}

	// handel response errors
	if resp.StatusCode != DefaultResponseCode {
		if rks.RuckusError != nil && rks.ErrorCode != nil {
			rks.RuckusError = &rksErr
		}
		if rks.debug {
			log.Println("Http Status Code:", resp.StatusCode)
			log.Println("Http Status:", resp.Status)
			log.Println("Ruckus Error Code:", rks.GetErrorCode())
			log.Println("Ruckus Error Type:", rks.GetErrorType())
			log.Println("Ruckus Message:", rks.GetMessage())
		}
		return rks.setErr(errors.New(resp.Status))
	}

	return nil
}

// L2 Access Control => Modify Rule Macs
// Modify a specific L2 Access Control Rule Macs.
// response code should be 204
func (rks *Ruckus) DeleteMacsToL2acl(mac ...string) error {
	if rks.Err() != nil {
		return rks.Err()
	}

	if rks.GetZoneId() == "" {
		return rks.setErr(fmt.Errorf("run %s method first", setZoneByNameMethod))
	}
	if rks.GetL2aclId() == "" {
		return rks.setErr(fmt.Errorf("run %s method first", setL2aclByNameMethod))
	}

	// URL
	subURL := "/v6_1/rkszones/{zoneId}/l2ACL/{id}/ruleMacs"
	url := rks.baseURL + strings.Replace(strings.Replace(subURL, "{zoneId}", rks.GetZoneId(), 1), "{id}", rks.GetL2aclId(), 1)

	// default response code
	const DefaultResponseCode = http.StatusNoContent

	acl, err := rks.GetL2aclById(rks.GetL2aclId())
	if err != nil {
		return rks.setErr(err)
	}
	currentMacs := acl.RuleMacs
	// a slice copied from the current MACs and remove the MACs that pervided from user.
	newMacs := currentMacs[:]
	for i := 0; i < len(mac); i++ {
		if !IsCorrectMac(mac[i]) {
			rks.incorrectedMacs = append(rks.incorrectedMacs, mac[i])
		}

		for j := 0; j < len(newMacs); j++ {
			if mac[i] == newMacs[j] {
				newMacs = append(newMacs[:j], newMacs[j+1:]...)
			}
		}
	}
	bj, err := json.Marshal(&newMacs)
	if err != nil {
		return rks.setErr(err)
	}
	payload := bytes.NewReader(bj)

	// request
	req, err := http.NewRequest("PATCH", url, payload)
	if err != nil {
		return rks.setErr(err)
	}
	req.Header.Add("Content-Type", "application/json;charset=UTF-8")

	// send the request
	resp, err := rks.c.Do(req)
	if err != nil {
		return rks.setErr(err)
	}
	defer resp.Body.Close()

	// handel the response
	respByteJson, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return rks.setErr(err)
	}
	// check JSON integrity
	checkJson(&respByteJson)

	respJson := RuckusError{}
	if err := json.Unmarshal(respByteJson, &respJson); err != nil {
		return rks.setErr(err)
	}

	// handel the response errors
	if resp.StatusCode != DefaultResponseCode {
		if respJson.ErrorCode != nil {
			rks.RuckusError = &respJson
		}
		if rks.debug {
			log.Println("Http Status Code:", resp.StatusCode)
			log.Println("Http Status:", resp.Status)
			log.Println("Ruckus Error Code:", rks.GetErrorCode())
			log.Println("Ruckus Error Type:", rks.GetErrorType())
			log.Println("Ruckus Message:", rks.GetMessage())
		}
		return rks.setErr(errors.New(resp.Status))
	}

	if rks.GetIncorrectMacs() != nil {
		return rks.setErr(fmt.Errorf("incorrect MACs found: %v", rks.GetIncorrectMacs()))
	}

	return nil
}

// L2 Access Control => Modify Rule Macs
// Modify a specific L2 Access Control Rule Macs.
// response code should be 204
func (rks *Ruckus) AddMacsToL2acl(mac ...string) error {
	if rks.Err() != nil {
		return rks.Err()
	}

	if rks.GetZoneId() == "" {
		return rks.setErr(fmt.Errorf("run %s method first", setZoneByNameMethod))
	}
	if rks.GetL2aclId() == "" {
		return rks.setErr(fmt.Errorf("run %s method first", setL2aclByNameMethod))
	}

	// URL
	subURL := "/v6_1/rkszones/{zoneId}/l2ACL/{id}/ruleMacs"
	url := rks.baseURL + strings.Replace(strings.Replace(subURL, "{zoneId}", rks.GetZoneId(), 1), "{id}", rks.GetL2aclId(), 1)

	// response 204
	const DefaultResponseCode = http.StatusNoContent

	// get old macs
	acl, err := rks.GetL2aclById(rks.GetL2aclId())
	if err != nil {
		return rks.setErr(err)
	}
	currentMacs := acl.RuleMacs

	// check MAC integrity
	rks.checkMacs(mac...)
	if rks.Err() != nil {
		return rks.setErr(rks.Err())
	}

	// append old macs and new macs
	newMacs := []string{}
	newMacs = append(newMacs, rks.GetCorrectMacs()...)
	newMacs = append(newMacs, currentMacs...)

	// to lower all the macs
	for i, v := range newMacs {
		newMacs[i] = strings.ToLower(v)
	}

	// trun data into JSON
	bJson, err := json.Marshal(&newMacs)
	if err != nil {
		return rks.setErr(err)
	}
	payload := bytes.NewReader(bJson)

	// request
	req, err := http.NewRequest("PATCH", url, payload)
	if err != nil {
		return rks.setErr(err)
	}
	req.Header.Add("Content-Type", "application/json;charset=UTF-8")

	resp, err := rks.c.Do(req)
	if err != nil {
		return rks.setErr(err)
	}
	defer resp.Body.Close()

	bj, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return rks.setErr(err)
	}
	// check JSON integrity
	checkJson(&bj)

	newACL := L2acl{}
	rksErr := RuckusError{}
	if err := json.Unmarshal(bj, &struct {
		*L2acl
		*RuckusError
	}{
		&newACL,
		&rksErr,
	}); err != nil {
		return rks.setErr(err)
	}

	if resp.StatusCode != DefaultResponseCode {
		if rksErr.ErrorCode != nil {
			rks.RuckusError = &rksErr
		}
		if rks.debug {
			log.Println("Http Status Code:", resp.StatusCode)
			log.Println("Http Status:", resp.Status)
			log.Println("Ruckus Error Code:", rks.GetErrorCode())
			log.Println("Ruckus Error Type:", rks.GetErrorType())
			log.Println("Ruckus Message:", rks.GetMessage())
		}

		return rks.setErr(errors.New(resp.Status))
	}

	return nil
}

// L2 Access Control => Create L2 Access Control
// Create a new L2 Access Control.
// response status code should be 201
func (rks *Ruckus) CreateL2ACL(aclName string, restriction string, description string, macs ...string) *Ruckus {
	if rks.Err() != nil {
		return rks
	}

	if rks.GetZoneId() == "" {
		rks.setErr(fmt.Errorf("run %s method first", setZoneByNameMethod))
		return rks
	}

	subURL := "/v6_1/rkszones/{zoneId}/l2ACL"
	url := rks.baseURL + strings.Replace(subURL, "{zoneId}", rks.GetZoneId(), 1)

	// response 201
	const DefaultResponseCode = http.StatusCreated

	// payload
	acl := struct {
		*L2acl
		Id     bool `json:"id,omitempty"`
		ZoneId bool `json:"zoneId,omitempty"`
	}{
		L2acl: &L2acl{
			Name:        aclName,
			Description: description,
		},
	}

	if restriction != L2ACL_Restriction_ALLOW && restriction != L2ACL_Restriction_BLOCK {
		rks.setErr(errors.New("restriction should be either ALLOW nor BLOCK"))
		return rks
	}
	acl.Restriction = restriction

	rks.CheckMacsWithNoDuplitation(macs...)
	if rks.Err() != nil {
		return rks
	}
	if rks.GetCorrectMacs() != nil {
		acl.RuleMacs = append(acl.RuleMacs, rks.GetCorrectMacs()...)
	}

	bytePayload, err := json.Marshal(&acl)
	if err != nil {
		if rks.debug {
			log.Println(err)
		}
		rks.setErr(err)
		return rks
	}
	payload := bytes.NewReader(bytePayload)

	// request
	req, err := http.NewRequest("POST", url, payload)
	if err != nil {
		if rks.debug {
			log.Println(err)
		}
		rks.setErr(err)
		return rks
	}
	req.Header.Add("Content-Type", "application/json;charset=UTF-8")

	// send the request
	resp, err := rks.c.Do(req)
	if err != nil {
		if rks.debug {
			log.Println(err)
		}
		rks.setErr(err)
		return rks
	}
	defer resp.Body.Close()

	// read the response
	bj, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		if rks.debug {
			log.Println(err)
		}
		rks.setErr(err)
		return rks
	}
	// check JSON integrity
	checkJson(&bj)

	// trun JSON data to Go Struct
	rltAcl := L2acl{}
	rksErr := RuckusError{}
	if err := json.Unmarshal(bj, &struct {
		*L2acl
		*RuckusError
	}{
		&rltAcl,
		&rksErr,
	}); err != nil {
		if rks.debug {
			log.Println(err)
		}
		rks.setErr(err)
		return rks
	}

	// check the response status
	if resp.StatusCode != DefaultResponseCode {
		if rksErr.ErrorCode != nil {
			rks.RuckusError = &rksErr
		}
		if rks.debug {
			log.Println("Http Status Code:", resp.StatusCode)
			log.Println("Http Status:", resp.Status)
			log.Println("Ruckus Error Code:", rks.GetErrorCode())
			log.Println("Ruckus Error Type:", rks.GetErrorType())
			log.Println("Ruckus Message:", rks.GetMessage())
		}
		rks.setErr(errors.New(resp.Status))
		return rks
	}

	return rks
}

func (rks *Ruckus) GetL2acls() ([]L2acl, error) {
	if rks.Err() != nil {
		return nil, rks.Err()
	}

	aclList, err := rks.GetL2aclList()
	if err != nil {
		return nil, rks.setErr(err)
	}

	rlt := []L2acl{}
	// loop over l2 acl list
	for _, l := range aclList {
		acl, err := rks.GetL2aclByName(l.Name)
		if err != nil {
			return nil, rks.setErr(err)
		}
		rlt = append(rlt, acl)
	}

	return rlt, nil
}

// L2 Access Control => Retrieve List
// Retrieve a list of L2 Access Control.
// response code should be 200
func (rks *Ruckus) GetL2aclList() ([]L2acl, error) {
	if rks.Err() != nil {
		return nil, rks.Err()
	}

	if rks.GetZoneId() == "" {
		return nil, rks.setErr(fmt.Errorf("run %s method first", setZoneByNameMethod))
	}

	// URL
	subUrl := "/v6_1/rkszones/{zoneId}/l2ACL"
	url := rks.baseURL + strings.Replace(subUrl, "{zoneId}", rks.GetZoneId(), 1)

	// response code
	DefaultResponseCode := http.StatusOK

	// request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, rks.setErr(err)
	}
	req.Header.Add("Content-Type", "application/json;charset=UTF-8")

	// send the request
	resp, err := rks.c.Do(req)
	if err != nil {
		return nil, rks.setErr(err)
	}
	defer resp.Body.Close()

	// read the response
	bj, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, rks.setErr(err)
	}
	// check JSON integrity
	checkJson(&bj)

	// convert the response JSON data to Go struct
	rksGen := RuckusGeneral{}
	acls := []L2acl{}
	rksErr := RuckusError{}

	if err := json.Unmarshal(bj, &struct {
		*RuckusGeneral
		List *[]L2acl
		*RuckusError
	}{
		RuckusGeneral: &rksGen,
		List:          &acls,
		RuckusError:   &rksErr,
	}); err != nil {
		return nil, rks.setErr(err)
	}

	// handle the response
	if resp.StatusCode != DefaultResponseCode {
		if rksErr.ErrorCode != nil {
			rks.RuckusError = &rksErr
		}
		if rks.debug {
			log.Println("Http Status Code:", resp.StatusCode)
			log.Println("Http Status:", resp.Status)
			log.Println("Ruckus Error Code:", rks.GetErrorCode())
			log.Println("Ruckus Error Type:", rks.GetErrorType())
			log.Println("Ruckus Message:", rks.GetMessage())
		}

		return nil, rks.setErr(errors.New(resp.Status))
	}

	return acls, nil
}

// L2 Access Control => Retrieve
// Retrieve an L2 Access Control.
// response code should be 200
func (rks *Ruckus) GetL2aclByName(name string) (L2acl, error) {
	if rks.Err() != nil {
		return L2acl{}, rks.Err()
	}

	if rks.GetZoneId() == "" {
		return L2acl{}, rks.setErr(fmt.Errorf("run %s method first", setZoneByNameMethod))
	}

	// check the input arguments
	l2aclName := name
	if l2aclName == "" {
		return L2acl{}, rks.setErr(errors.New("id can not be empty"))
	}

	// loop over l2 acl list to get Id by Name
	l2aclId := ""
	l2aclList, err := rks.GetL2aclList()
	if err != nil {
		return L2acl{}, rks.setErr(err)
	}
	for _, acl := range l2aclList {
		if l2aclName == acl.Name {
			l2aclId = acl.Id
			break
		}
	}

	// Url
	subURL := "/v6_1/rkszones/{zoneId}/l2ACL/{id}"
	url := rks.baseURL + strings.Replace(strings.Replace(subURL, "{zoneId}", rks.GetZoneId(), 1), "{id}", l2aclId, 1)

	// response 200
	const DefaultResponseCode = http.StatusOK

	// request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return L2acl{}, rks.setErr(err)
	}
	req.Header.Add("Content-Type", "application/json;charset=UTF-8")

	// send the request
	resp, err := rks.c.Do(req)
	if err != nil {
		return L2acl{}, rks.setErr(err)
	}
	defer resp.Body.Close()

	// read the response
	bj, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return L2acl{}, rks.setErr(err)
	}
	// check JSON integrity
	checkJson(&bj)

	// convert response data to Go strct
	acl := L2acl{}
	rksErr := RuckusError{}
	if err = json.Unmarshal(bj, &struct {
		*L2acl
		*RuckusError
	}{
		&acl,
		&rksErr,
	}); err != nil {
		return L2acl{}, rks.setErr(err)
	}

	// handel the response status
	if resp.StatusCode != DefaultResponseCode {
		if rksErr.ErrorCode != nil {
			rks.RuckusError = &rksErr
		}
		if rks.debug {
			log.Println("Http Status Code:", resp.StatusCode)
			log.Println("Http Status:", resp.Status)
			log.Println("Ruckus Error Code:", rks.GetErrorCode())
			log.Println("Ruckus Error Type:", rks.GetErrorType())
			log.Println("Ruckus Message:", rks.GetMessage())
		}
		return L2acl{}, rks.setErr(errors.New(resp.Status))
	}

	return acl, nil
}

// L2 Access Control => Retrieve
// Retrieve an L2 Access Control.
// response code should be 200
func (rks *Ruckus) GetL2aclById(id string) (L2acl, error) {
	if rks.Err() != nil {
		return L2acl{}, rks.Err()
	}

	if rks.GetZoneId() == "" {
		return L2acl{}, rks.setErr(fmt.Errorf("run %s method first", setZoneByNameMethod))
	}

	l2aclId := id
	if l2aclId == "" {
		return L2acl{}, rks.setErr(errors.New("id can not be empty"))
	}

	subURL := "/v6_1/rkszones/{zoneId}/l2ACL/{id}"
	url := rks.baseURL + strings.Replace(strings.Replace(subURL, "{zoneId}", rks.GetZoneId(), 1), "{id}", l2aclId, 1)

	// response 200
	const DefaultResponseCode = http.StatusOK

	// request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return L2acl{}, rks.setErr(err)
	}
	req.Header.Add("Content-Type", "application/json;charset=UTF-8")

	// send the request
	resp, err := rks.c.Do(req)
	if err != nil {
		return L2acl{}, rks.setErr(err)
	}
	defer resp.Body.Close()

	// read the response
	bj, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return L2acl{}, rks.setErr(err)
	}
	// check JSON integrity
	checkJson(&bj)

	// convert response data to Go strct
	acl := L2acl{}
	rksErr := RuckusError{}
	if err = json.Unmarshal(bj, &struct {
		*L2acl
		*RuckusError
	}{
		&acl,
		&rksErr,
	}); err != nil {
		return L2acl{}, rks.setErr(err)
	}

	// handel the response status
	if resp.StatusCode != DefaultResponseCode {
		if rksErr.ErrorCode != nil {
			rks.RuckusError = &rksErr
		}
		if rks.debug {
			log.Println("Http Status Code:", resp.StatusCode)
			log.Println("Http Status:", resp.Status)
			log.Println("Ruckus Error Code:", rks.GetErrorCode())
			log.Println("Ruckus Error Type:", rks.GetErrorType())
			log.Println("Ruckus Message:", rks.GetMessage())
		}
		return L2acl{}, rks.setErr(errors.New(resp.Status))
	}

	return acl, nil
}

// L2 Access Control => Retrieve
// Retrieve an L2 Access Control.
// response code should be 200
func (rks *Ruckus) GetL2acl() (L2acl, error) {
	if rks.Err() != nil {
		return L2acl{}, rks.Err()
	}

	if rks.GetZoneId() == "" {
		return L2acl{}, rks.setErr(fmt.Errorf("run %s method first", setZoneByNameMethod))
	}
	if rks.GetL2aclId() == "" {
		return L2acl{}, rks.setErr(fmt.Errorf("run %s method first", setL2aclByNameMethod))
	}

	// Url
	subURL := "/v6_1/rkszones/{zoneId}/l2ACL/{id}"
	url := rks.baseURL + strings.Replace(strings.Replace(subURL, "{zoneId}", rks.GetZoneId(), 1), "{id}", rks.GetL2aclId(), 1)

	// response 200
	const DefaultResponseCode = http.StatusOK

	// request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return L2acl{}, rks.setErr(err)
	}
	req.Header.Add("Content-Type", "application/json;charset=UTF-8")

	// send the request
	resp, err := rks.c.Do(req)
	if err != nil {
		return L2acl{}, rks.setErr(err)
	}
	defer resp.Body.Close()

	// read the response
	bj, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return L2acl{}, rks.setErr(err)
	}
	// check JSON integrity
	checkJson(&bj)

	// convert response data to Go strct
	acl := L2acl{}
	rksErr := RuckusError{}
	if err = json.Unmarshal(bj, &struct {
		*L2acl
		*RuckusError
	}{
		&acl,
		&rksErr,
	}); err != nil {
		return L2acl{}, rks.setErr(err)
	}

	// handel the response status
	if resp.StatusCode != DefaultResponseCode {
		if rksErr.ErrorCode != nil {
			rks.RuckusError = &rksErr
		}
		if rks.debug {
			log.Println("Http Status Code:", resp.StatusCode)
			log.Println("Http Status:", resp.Status)
			log.Println("Ruckus Error Code:", rks.GetErrorCode())
			log.Println("Ruckus Error Type:", rks.GetErrorType())
			log.Println("Ruckus Message:", rks.GetMessage())
		}
		return L2acl{}, rks.setErr(errors.New(resp.Status))
	}

	return acl, nil
}

func (rks *Ruckus) GetClients() (
	[]struct {
		Client
		Ap
	},
	error) {
	if rks.Err() != nil {
		return nil, rks.Err()
	}

	clients := []struct {
		Client
		Ap
	}{}

	// get the ap list
	aps, err := rks.GetAps()
	if err != nil {
		return nil, rks.setErr(err)
	}
	// loop over the ap list
	for _, a := range aps {
		cs, err := rks.GetClientsByApName(a.Name)
		if err != nil {
			return nil, rks.setErr(err)
		}
		for _, c := range cs {
			x := struct {
				Client
				Ap
			}{
				c,
				a,
			}
			clients = append(clients, x)
		}
	}

	return clients, nil
}

// Wireless Client => RETRIEVE CLIENT LIST
// Use this API command to retrieve the client list per AP.
// response code should be 200
func (rks *Ruckus) GetClientsByApName(apName string) ([]Client, error) {
	if apName == "" {
		return nil, rks.setErr(errors.New("ap name can not be empty"))
	}

	if rks.Err() != nil {
		return nil, rks.Err()
	}

	// check input parameters
	aps, err := rks.GetAps()
	if err != nil {
		return nil, rks.setErr(err)
	}

	apMac := ""
	for _, ap := range aps {
		if strings.EqualFold(ap.Name, apName) {
			apMac = ap.Mac
		}
	}
	if apMac == "" {
		return nil, rks.setErr(errors.New("ap name doesn't exist"))
	}

	// set the default response code
	const DefaultResponseCode = http.StatusOK

	// URL
	subURL := "/v6_1/aps/{apMac}/operational/client"
	url := rks.baseURL + strings.Replace(subURL, "{apMac}", apMac, 1)

	// request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, rks.setErr(err)
	}
	req.Header.Add("Content-Type", "application/json;charset=UTF-8")

	// send the request
	resp, err := rks.c.Do(req)
	if err != nil {
		return nil, rks.setErr(err)
	}
	defer resp.Body.Close()

	// read the response
	bj, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, rks.setErr(err)
	}
	checkJson(&bj)

	// convert response to Go struct
	rksGen := RuckusGeneral{}
	clients := []Client{}
	rksErr := RuckusError{}

	if err := json.Unmarshal(bj, &struct {
		*RuckusGeneral
		List *[]Client
		*RuckusError
	}{
		&rksGen,
		&clients,
		&rksErr,
	}); err != nil {
		return nil, rks.setErr(err)
	}

	// handel the response status
	if resp.StatusCode != DefaultResponseCode {
		if rksErr.ErrorCode != nil {
			rks.RuckusError = &rksErr
		}
		if rks.debug {
			log.Println("Http Status Code:", resp.StatusCode)
			log.Println("Http Status:", resp.Status)
			log.Println("Ruckus Error Code:", rks.GetErrorCode())
			log.Println("Ruckus Error Type:", rks.GetErrorType())
			log.Println("Ruckus Message:", rks.GetMessage())
		}
		return nil, rks.setErr(errors.New(resp.Status))
	}

	return clients, nil
}

// Ruckus Wireless AP Zone => Retrieve List
// Use this API command to retrieve the list of Ruckus Wireless AP zones that belong to a domain.
// response code should be 200
func (rks *Ruckus) GetZones() ([]Zone, error) {
	if rks.Err() != nil {
		return nil, rks.Err()
	}

	subURL := "/v6_1/rkszones"
	url := rks.baseURL + subURL

	// response 200
	const DefaultResponseCode = http.StatusOK

	// request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, rks.setErr(err)
	}
	req.Header.Add("Content-Type", "application/json;charset=UTF-8")

	// send the request
	resp, err := rks.c.Do(req)
	if err != nil {
		return nil, rks.setErr(err)
	}
	defer resp.Body.Close()

	// handel the response
	bj, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, rks.setErr(err)
	}
	// check JSON integrity
	checkJson(&bj)

	rksGen := RuckusGeneral{}
	zones := []Zone{}
	rksErr := RuckusError{}

	err = json.Unmarshal(bj, &struct {
		*RuckusGeneral
		List *[]Zone
		*RuckusError
	}{
		&rksGen,
		&zones,
		&rksErr,
	})
	if err != nil {
		return nil, rks.setErr(err)
	}

	if resp.StatusCode != DefaultResponseCode {
		if rksErr.ErrorCode != nil {
			rks.RuckusError = &rksErr
		}
		if rks.debug {
			log.Println("Http Status Code:", resp.StatusCode)
			log.Println("Http Status:", resp.Status)
			log.Println("Ruckus Error Code:", rks.GetErrorCode())
			log.Println("Ruckus Error Type:", rks.GetErrorType())
			log.Println("Ruckus Message:", rks.GetMessage())
		}

		return nil, rks.setErr(errors.New(resp.Status))
	}

	return zones, nil
}

// Access Point Configuration => Retrieve List
// Use this API command to retrieve the list of APs that belong to a zone or a domain.
// response code should be 200
func (rks *Ruckus) GetAps() ([]Ap, error) {
	if rks.Err() != nil {
		return nil, rks.Err()
	}

	subURL := "/v6_1/aps"
	url := rks.baseURL + subURL

	// response 200
	const DefaultResponseCode = http.StatusOK

	// send the request
	resp, err := rks.c.Get(url)
	if err != nil {
		return nil, rks.setErr(err)
	}
	defer resp.Body.Close()

	// read the response body
	bj, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, rks.setErr(err)
	}
	// check JSON integrity
	checkJson(&bj)

	rksGen := RuckusGeneral{}
	aps := []Ap{}
	rksErr := RuckusError{}

	err = json.Unmarshal(bj, &struct {
		*RuckusGeneral
		List *[]Ap
		*RuckusError
	}{
		&rksGen,
		&aps,
		&rksErr,
	})
	if err != nil {
		return nil, rks.setErr(err)
	}

	if resp.StatusCode != DefaultResponseCode {
		if rksErr.ErrorCode != nil {
			rks.RuckusError = &rksErr
		}
		if rks.debug {
			log.Println("Http Status Code:", resp.StatusCode)
			log.Println("Http Status:", resp.Status)
			log.Println("Ruckus Error Code:", rks.GetErrorCode())
			log.Println("Ruckus Error Type:", rks.GetErrorType())
			log.Println("Ruckus Message:", rks.GetMessage())
		}
		return nil, rks.setErr(errors.New(resp.Status))
	}

	return aps, nil
}

func (rks *Ruckus) Close() error {
	return rks.Logoff()
}

//  Sessions => Logoff
// Use this API command to log off of the controller.
func (rks *Ruckus) Logoff() error {
	subURL := "/v6_1/session"
	url := rks.baseURL + subURL

	// response 200
	const DefaultResponseCode = http.StatusOK

	// request
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		if rks.debug {
			log.Println(err)
		}
		return rks.setErr(err)
	}
	req.Header.Add("Content-Type", "application/json;charset=UTF-8")

	// send the request
	resp, err := rks.c.Do(req)
	if err != nil {
		if rks.debug {
			log.Println(err)
		}
		return rks.setErr(err)
	}
	defer resp.Body.Close()

	// read the response body
	bj, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		if rks.debug {
			log.Println(err)
		}
		return rks.setErr(err)
	}
	// check JSON integrity
	checkJson(&bj)

	// unmarshal the body(JSON)
	rksErr := RuckusError{}
	if err := json.Unmarshal(bj, &rksErr); err != nil {
		if rks.debug {
			log.Println(err)
		}
		return rks.setErr(err)
	}

	// handel the error
	if resp.StatusCode != DefaultResponseCode {
		if rksErr.ErrorCode != nil {
			rks.RuckusError = &rksErr
		}
		if rks.debug {
			log.Println("Http Status Code:", resp.StatusCode)
			log.Println("Http Status:", resp.Status)
			log.Println("Ruckus Error Code:", rks.GetErrorCode())
			log.Println("Ruckus Error Type:", rks.GetErrorType())
			log.Println("Ruckus Message:", rks.GetMessage())
		}
		return rks.setErr(errors.New(resp.Status))
	}

	return nil
}

// Logon Sessions => Logon
// Use this API command to log on to the controller and acquire a valid logon session.
func (rks *Ruckus) Logon(username string, password string) error {
	subURL := "/v6_1/session"
	url := rks.baseURL + subURL

	// response 200
	const DefaultResponseCode = http.StatusOK

	// payload
	LogonInfo, err := json.Marshal(NewLogonSessions(username, password))
	if err != nil {
		if rks.debug {
			log.Println(err)
		}
		return rks.setErr(err)
	}
	payload := bytes.NewReader(LogonInfo)

	// request
	req, err := http.NewRequest("POST", url, payload)
	if err != nil {
		if rks.debug {
			log.Println(err)
		}
		return rks.setErr(err)
	}

	// send the request
	resp, err := rks.c.Do(req)
	if err != nil {
		if rks.debug {
			log.Println(err)
		}
		return rks.setErr(err)
	}
	defer resp.Body.Close()

	// read the response body
	bj, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		if rks.debug {
			log.Println(err)
		}
		return rks.setErr(err)
	}
	// check JSON integrity
	checkJson(&bj)

	// unmarshal the body(JSON)
	rksErr := RuckusError{}
	if err := json.Unmarshal(bj, &rksErr); err != nil {
		if rks.debug {
			log.Println(err)
		}
		return rks.setErr(err)
	}

	// handel the error
	if resp.StatusCode != DefaultResponseCode {
		if rksErr.ErrorCode != nil {
			rks.RuckusError = &rksErr
		}
		if rks.debug {
			log.Println("Http Status Code:", resp.StatusCode)
			log.Println("Http Status:", resp.Status)
			log.Println("Ruckus Error Code:", rks.GetErrorCode())
			log.Println("Ruckus Error Type:", rks.GetErrorType())
			log.Println("Ruckus Message:", rks.GetMessage())
		}
		return rks.setErr(errors.New(resp.Status))
	}

	return nil
}

func (rks *Ruckus) GetMessage() string {
	if rks.RuckusError != nil {
		return *rks.Message
	}
	return ""
}

func (rks *Ruckus) GetErrorCode() int {
	if rks.RuckusError != nil {
		return *rks.ErrorCode
	}
	return 0
}

func (rks *Ruckus) GetErrorType() string {
	if rks.RuckusError != nil {
		return *rks.ErrorType
	}
	return ""
}

func ClearMacs(rks *Ruckus) {
	rks.incorrectedMacs = nil
	rks.duplicatedMacs = nil
	rks.correctedMacs = nil
}

func (rks *Ruckus) Err() error {
	return rks.err
}

func (rks *Ruckus) setErr(err error) error {
	rks.err = err
	return rks.Err()
}

func checkJson(bj *[]byte) {
	if len(*bj) == 0 {
		*bj = []byte("{}")
	}
}
