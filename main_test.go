package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	// "fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAddStudent(t *testing.T) {
	var jsonStr = []byte(`{"studentid":"1010","studentname":"rani","email":"rani@gmail.com"}`)

	req, err := http.NewRequest("POST", "/addstudent", bytes.NewBuffer(jsonStr))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(AddStudent)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	expected := map[string]string{"studentid": "1010", "studentname": "rani", "email": "rani@gmail.com"}

	var got map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Errorf("Cannot unmarshal resp to interafce, err=%v", err)
	}
	// fmt.Println(got)
	// t.Errorf("got=%v\nexpected=%v", got["data"].([]interface{})[0], expected)

	if strings.Compare(fmt.Sprintf("%v", got["data"].([]interface{})[0]), fmt.Sprintf("%v", expected)) != 0 {
		t.Errorf("handler returned unexpected body: got %s want %v", rr.Body.String(), expected)
	}

}

func TestGetAllLeaveApproves(t *testing.T) {
	req, err := http.NewRequest("GET", "/getallleaveapproves", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(GetAllLeaveApproves)
	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
	// Check the response body is what we expect.
	expected := map[string]string{"studentid": "1010", "studentname": "rani", "email": "rani@gmail.com"}
	var got map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Errorf("Cannot unmarshal resp to interafce, err=%v", err)
	}

	if strings.Compare(fmt.Sprintf("%v", got["data"].([]interface{})[0]), fmt.Sprintf("%v", expected)) != 0 {
		t.Errorf("handler returned unexpected body: got %s want %v", rr.Body.String(), expected)
	}
}


func TestSetAdminCredentials(t *testing.T) {
	var jsonStr = []byte(`{"adminname":"chandini","password":"chandini@123"}`)
	req, err := http.NewRequest("POST", "/setadmincredentials", bytes.NewBuffer(jsonStr))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(SetAdminCredentials)
	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	expected := map[string]string{"adminname": "chandini", "password": "c60041297879c919208d750e0361bb5435246ca093457a73aa21c5874fb31053"}

	var got map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Errorf("Cannot unmarshal resp to interafce, err=%v", err)
	}

	if strings.Compare(fmt.Sprintf("%v", got["data"].([]interface{})[0]), fmt.Sprintf("%v", expected)) != 0 {
		t.Errorf("handler returned unexpected body: got %s want %v", rr.Body.String(), expected)
	}

}

func TestSetStudentCredentials(t *testing.T) {
	var jsonStr = []byte(`{"studentid":"1018","studentname":"seeta","password":"seeta@123"}`)
	req, err := http.NewRequest("POST", "/setstudentcredentials", bytes.NewBuffer(jsonStr))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(SetStudentCredentials)
	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	expected := map[string]string{"studentid": "1018", "studentname": "seeta", "password": "c741480332e9a5d2947c930696e4d8ad91533e5120c2b06d549d7f9961c84a1c"}

	var got map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Errorf("Cannot unmarshal resp to interafce, err=%v", err)
	}

	if strings.Compare(fmt.Sprintf("%v", got["data"].([]interface{})[0]), fmt.Sprintf("%v", expected)) != 0 {
		t.Errorf("handler returned unexpected body: got %s want %v", rr.Body.String(), expected)
	}

}

func TestAddLeaveRequest(t *testing.T) {
	var jsonStr = []byte(`{"studentid":"1010","studentname":"rani","reason":"fever","status":"pending","dates":"14-2-23 to 16-2-23"}`)

	req, err := http.NewRequest("POST", "/addleaverequest", bytes.NewBuffer(jsonStr))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(AddLeaveRequest)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	expected := map[string]string{"studentid": "1010", "studentname": "rani", "Reason": "fever", "status": "pending", "dates": "14-2-23 to 16-2-23"}

	var got map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Errorf("Cannot unmarshal resp to interafce, err=%v", err)
	}

	if strings.Compare(fmt.Sprintf("%v", got["data"].([]interface{})[0]), fmt.Sprintf("%v", expected)) != 0 {
		t.Errorf("handler returned unexpected body: got %s want %v", rr.Body.String(), expected)
	}

}

func TestAddApprovedLeaves(t *testing.T) {
	var jsonStr = []byte(`{"studentid":"1010","studentname":"rani","email":"rani@gmail.com"}`)

	req, err := http.NewRequest("POST", "/addapprovedleaves", bytes.NewBuffer(jsonStr))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(AddApprovedLeaves)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	expected := map[string]string{"studentid": "1010", "studentname": "rani", "email": "rani@gmail.com"}

	var got map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Errorf("Cannot unmarshal resp to interafce, err=%v", err)
	}

	if strings.Compare(fmt.Sprintf("%v", got["data"].([]interface{})[0]), fmt.Sprintf("%v", expected)) != 0 {
		t.Errorf("handler returned unexpected body: got %s want %v", rr.Body.String(), expected)
	}
}

