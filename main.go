package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"go.mongodb.org/mongo-driver/bson"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var db *mongo.Client

var mongoCtx context.Context

var studentdb *mongo.Collection
var leaverequestdb *mongo.Collection
var leaveapprovedb *mongo.Collection
var userdetailsdb *mongo.Collection
var admindb *mongo.Collection

const studentCollection = "Student"
const leaverequestCollection = "Leaverequests"
const leaveapproveCollection = "Leaveapproves"
const userdetailsCollection = "Userdetails"
const leavemanagement = "Leavemanagement"
const adminCollection = "Admin"

func init() {
	mongoCtx = context.Background()
	db, err := mongo.Connect(mongoCtx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		log.Fatal(err)
	}
	err = db.Ping(mongoCtx, nil)
	if err != nil {
		log.Fatalf("could not  connect to MongoDb: %v", err)
	} else {
		fmt.Println("Connected to MongoDB")
	}

	studentdb = db.Database(leavemanagement).Collection(studentCollection)
	admindb = db.Database(leavemanagement).Collection(adminCollection)
	leaverequestdb = db.Database(leavemanagement).Collection(leaverequestCollection)
	leaveapprovedb = db.Database(leavemanagement).Collection(leaveapproveCollection)
	userdetailsdb = db.Database(leavemanagement).Collection(userdetailsCollection)
}

type Student struct {
	StudentID   string `json:"studentid"`
	StudentName string `json:"studentname"`
	Email       string `json:"email"`
	Status      string `json:"status"`
}

type StudentCredentails struct {
	StudentID   string `json:"studentid"`
	StudentName string `json:"studentname"`
	Password    string `json:"password"`
}

type AdminCredentials struct {
	AdminName     string `json:"adminname`
	AdminPassword string `json:"password`
}

type LeaveRequest struct {
	StudentID   string `json:"studentid"`
	StudentName string `json:"studentname"`
	Reason      string `json:"Reason"`
	Status      string `json:"status"`
	Dates       string `json:"dates"`
}

type LeaveApproved struct {
	StudentID   string `json:"studentid"`
	StudentName string `json:"studentname"`
	Email       string `json:"email"`
}

type Login struct {
	Name     string `json:"studentname"`
	Password string `json:"password"`
}

// Claims is  a struct that will be encoded to a JWT.
type Claims struct {
	Name               string
	jwt.StandardClaims // jwt.StandardClaims is an embedded type to provide expiry time
}
type JsonResponseLogin struct {
	Status  int    `json:"type"`
	Token   string `json:"token"`
	Invalid bool   `json:"invalid"`
	Message string `json:"message"`
}

type JsonResponseStudent struct {
	Status  int       `json:"type"`
	Data    []Student `json:"data"`
	Message string    `json:"message"`
}

type JsonResponseStudentCredentials struct {
	Status  int                  `json:"type"`
	Data    []StudentCredentails `json:"data"`
	Message string               `json:"message"`
}

type JsonResponseAdminCredentials struct {
	Status  int                `json:"type"`
	Data    []AdminCredentials `json:"data"`
	Message string             `json:"message"`
}

type JsonResponseLeaveRequest struct {
	Status  int            `json:"type"`
	Data    []LeaveRequest `json:"data"`
	Message string         `json:"message"`
}

type JsonResponseLeaveApproved struct {
	Status  int             `json:"type"`
	Data    []LeaveApproved `json:"data"`
	Message string          `json:"message"`
}

type ErrorResponse struct {
	Status  int    `json:"type"`
	Message string `json:"message"`
}

// SuccessResponse is struct for sending error message with code.
type SuccessResponse struct {
	Status   int
	Message  string
	Response interface{}
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/addstudent", AddStudent).Methods("POST")
	r.HandleFunc("/setstudentcredentials", SetStudentCredentials).Methods("POST")
	r.HandleFunc("/addleaverequest", AddLeaveRequest).Methods("POST")
	r.HandleFunc("/getleaverequests", GetLeaveRequests).Methods("GET")
	r.HandleFunc("/getallstudents", GetAllStudents).Methods("GET")
	r.HandleFunc("/addleaveapproves", AddApprovedLeaves).Methods("POST")
	r.HandleFunc("/getallleaveapproves", GetAllLeaveApproves).Methods("GET")
	r.HandleFunc("/studentlogin", StudentLogin).Methods("POST")
	r.HandleFunc("/setadmincredentials", SetAdminCredentials).Methods("POST")
	r.HandleFunc("/adminlogin", AdminLogin).Methods("POST")
	fmt.Println("attempting to start server")
	log.Fatal(http.ListenAndServe(":8000", r))
}

func printMessage(message string) {
	fmt.Println("")
	fmt.Println(message)
	fmt.Println("")
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

var jwtSecretKey = []byte("jwt_secret_key")

// CreateJWT func will used to create the JWT while signing in and signing out
func CreateJWT(name string) (response string, err error) {
	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Name: name,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecretKey)
	if err == nil {
		return tokenString, nil
	}
	return "", err
}

// VerifyToken func will used to Verify the JWT Token while using APIS
func VerifyToken(tokenString string) (name string, err error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecretKey, nil
	})

	if token != nil {
		return claims.Name, nil
	}
	return "", err
}

//this function is used for student login with name and password
func StudentLogin(w http.ResponseWriter, r *http.Request) {
	var loginRequest Login
	var result Student

	json.NewDecoder(r.Body).Decode(&loginRequest)

	if loginRequest.Name == "" {
		json.NewEncoder(w).Encode(ErrorResponse{
			Status:  400,
			Message: "Last Name can't be empty",
		})
	} else if loginRequest.Password == "" {
		json.NewEncoder(w).Encode(ErrorResponse{
			Status:  400,
			Message: "cant add the student will null values1",
		})
	} else {

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		hashpassword := loginRequest.Password
		h := sha256.New()
		h.Write([]byte(hashpassword))
		loginRequest.Password = hex.EncodeToString(h.Sum(nil))
		var err = userdetailsdb.FindOne(ctx, bson.M{
			"studentname": loginRequest.Name,
			"password":    loginRequest.Password,
		}).Decode(&result)

		defer cancel()

		if err != nil {
			json.NewEncoder(w).Encode(ErrorResponse{
				Status:  400,
				Message: fmt.Sprintf("cant add the student will null values2. err=", err),
			})
		} else {
			tokenString, _ := CreateJWT(loginRequest.Name)

			if tokenString == "" {
				json.NewEncoder(w).Encode(ErrorResponse{
					Status:  400,
					Message: "cant add the student will null values3",
				})
			}
			var successResponse = SuccessResponse{
				Status:  http.StatusOK,
				Message: "You are registered, login again",
				Response: JsonResponseLogin{
					Status:  200,
					Token:   tokenString,
					Invalid: false,
					Message: fmt.Sprintf("successful login %s ", loginRequest.Name),
					// AuthToken: tokenString,
					// Email:     loginRequest.Email,
				},
			}

			successJSONResponse, jsonError := json.Marshal(successResponse)

			if jsonError != nil {
				json.NewEncoder(w).Encode(ErrorResponse{
					Status:  400,
					Message: "cant add the student will null values4",
				})
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(successJSONResponse)
		}
	}
}

//this function is used for adminlogin with name and password
func AdminLogin(w http.ResponseWriter, r *http.Request) {
	var loginRequest AdminCredentials
	var result Student

	json.NewDecoder(r.Body).Decode(&loginRequest)

	if loginRequest.AdminName == "" {
		json.NewEncoder(w).Encode(ErrorResponse{
			Status:  400,
			Message: "Last Name can't be empty",
		})
	} else if loginRequest.AdminPassword == "" {
		json.NewEncoder(w).Encode(ErrorResponse{
			Status:  400,
			Message: "cant add the student will null values1",
		})
	} else {

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		hashpassword := loginRequest.AdminPassword
		h := sha256.New()
		h.Write([]byte(hashpassword))
		loginRequest.AdminPassword = hex.EncodeToString(h.Sum(nil))
		var err = userdetailsdb.FindOne(ctx, bson.M{
			"adminname": loginRequest.AdminName,
			"password":  loginRequest.AdminPassword,
		}).Decode(&result)

		defer cancel()

		if err != nil {
			json.NewEncoder(w).Encode(ErrorResponse{
				Status:  400,
				Message: fmt.Sprintf("cant add the student will null values2. err=", err),
			})
		} else {
			tokenString, _ := CreateJWT(loginRequest.AdminName)

			if tokenString == "" {
				json.NewEncoder(w).Encode(ErrorResponse{
					Status:  400,
					Message: "cant add the student will null values3",
				})
			}
			var successResponse = SuccessResponse{
				Status:  http.StatusOK,
				Message: "You are registered, login again",
				Response: JsonResponseLogin{
					Status:  200,
					Token:   tokenString,
					Invalid: false,
					Message: fmt.Sprintf("successful login %s ", loginRequest.AdminName),
					// AuthToken: tokenString,
					// Email:     loginRequest.Email,
				},
			}

			successJSONResponse, jsonError := json.Marshal(successResponse)

			if jsonError != nil {
				json.NewEncoder(w).Encode(ErrorResponse{
					Status:  400,
					Message: "cant add the student will null values4",
				})
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(successJSONResponse)
		}
	}
}

//this function is used to set AdminCredentials with name and password
func SetAdminCredentials(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var admin AdminCredentials
	json.NewDecoder(r.Body).Decode(&admin)
	fmt.Println("admin", admin)

	if admin.AdminName == "" || admin.AdminPassword == "" {
		json.NewEncoder(w).Encode(JsonResponseStudentCredentials{
			Status:  400,
			Message: "cant add the student will null values",
		})
	}
	hashpassword := admin.AdminPassword
	h := sha256.New()
	h.Write([]byte(hashpassword))
	admin.AdminPassword = hex.EncodeToString(h.Sum(nil))

	//inserting the students data into the database
	result, err := userdetailsdb.InsertOne(mongoCtx, admin)
	if err != nil {
		json.NewEncoder(w).Encode(JsonResponseAdminCredentials{
			Status:  400,
			Message: fmt.Sprintf("Internal error: %v", err),
		})
	}

	json.NewEncoder(w).Encode(JsonResponseAdminCredentials{
		Status:  200,
		Data:    []AdminCredentials{admin},
		Message: fmt.Sprintf("Admin added successfully: %s", result.InsertedID),
	})
}

//this function is used to set StudentCredentials with name and password and Id
func SetStudentCredentials(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var student StudentCredentails
	json.NewDecoder(r.Body).Decode(&student)
	fmt.Println("student", student)

	if student.StudentName == "" || student.StudentID == "" || student.Password == "" {
		json.NewEncoder(w).Encode(JsonResponseStudentCredentials{
			Status:  400,
			Message: "cant add the student will null values",
		})
	}
	hashpassword := student.Password
	h := sha256.New()
	h.Write([]byte(hashpassword))
	student.Password = hex.EncodeToString(h.Sum(nil))

	//inserting the students data into the database
	result, err := userdetailsdb.InsertOne(mongoCtx, student)
	if err != nil {
		json.NewEncoder(w).Encode(JsonResponseStudentCredentials{
			Status:  400,
			Message: fmt.Sprintf("Internal error: %v", err),
		})
	}

	json.NewEncoder(w).Encode(JsonResponseStudentCredentials{
		Status:  200,
		Data:    []StudentCredentails{student},
		Message: fmt.Sprintf("Student added successfully: %s", result.InsertedID),
	})
}

//this function inserts the student details into the database
func AddStudent(w http.ResponseWriter, r *http.Request) {
	var student Student
	json.NewDecoder(r.Body).Decode(&student)
	fmt.Println("student", student)

	if student.StudentName == "" || student.StudentID == "" || student.Email == "" {
		json.NewEncoder(w).Encode(JsonResponseStudent{
			Status:  400,
			Message: "cant add the student will null values",
		})
	}

	//inserting the students data into the database
	result, err := studentdb.InsertOne(mongoCtx, student)
	if err != nil {
		json.NewEncoder(w).Encode(JsonResponseStudent{
			Status:  400,
			Message: fmt.Sprintf("Internal error: %v", err),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(JsonResponseStudent{
		Status:  200,
		Data:    []Student{student},
		Message: fmt.Sprintf("Student added successfully: %s", result.InsertedID),
	})
}

//this func inserts the student leave request into the database
func AddLeaveRequest(w http.ResponseWriter, r *http.Request) {
	var student LeaveRequest
	json.NewDecoder(r.Body).Decode(&student)
	fmt.Println("leave request", student)

	if student.StudentName == "" || student.StudentID == "" || student.Dates == "" || student.Reason == "" {
		json.NewEncoder(w).Encode(JsonResponseStudent{
			Status:  400,
			Message: "cant add the student will null values",
		})
	}
	student.Status = "pending"
	//inserting the leave requests into the leave request database
	result, err := leaverequestdb.InsertOne(mongoCtx, student)
	if err != nil {
		json.NewEncoder(w).Encode(JsonResponseLeaveRequest{
			Status:  400,
			Message: fmt.Sprintf("Internal error: %v", err),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(JsonResponseLeaveRequest{
		Status:  200,
		Data:    []LeaveRequest{student},
		Message: fmt.Sprintf("Leave request added successfully: %s", result.InsertedID),
	})
}

// this func inserts the details of students whose leaves are approved into the database
func AddApprovedLeaves(w http.ResponseWriter, r *http.Request) {
	var approved LeaveApproved
	var status LeaveRequest
	json.NewDecoder(r.Body).Decode(&approved)
	fmt.Println("students approved", approved)

	if approved.StudentID == "" || approved.StudentName == "" || approved.Email == "" {
		json.NewEncoder(w).Encode(JsonResponseStudent{
			Status:  400,
			Message: "cant add the student will null values",
		})
	}
	// fmt.Println("hello")/
	status.Status = "accepted"
	filter := bson.M{
		"$set": bson.M{
			"status": status.Status,
		},
	}
	query := bson.M{
		"studentid": approved.StudentID,
	}

	// var a db.leaverequestdb
	//inserting the students whose leaves are approved into the database
	result, err := leaveapprovedb.InsertOne(mongoCtx, approved)

	if err != nil {
		json.NewEncoder(w).Encode(JsonResponseLeaveApproved{
			Status:  400,
			Message: fmt.Sprintf("Internal error: %v", err),
		})
	}
	_ = leaverequestdb.FindOneAndUpdate(mongoCtx, query, filter)

	// query := bson.M{
	// 	"studentid": approved.StudentID,
	// }
	// x, err1 := leaverequestdb.DeleteOne(mongoCtx, query)
	// if err1 != nil {
	// 	json.NewEncoder(w).Encode(JsonResponseLeaveApproved{
	// 		Status:  400,
	// 		Message: fmt.Sprintf("Internal error: %v", err1),
	// 	})
	// }
	// if x.DeletedCount == 0 {
	// 	json.NewEncoder(w).Encode(JsonResponseLeaveApproved{
	// 		Status:  400,
	// 		Message: "cant match the details",
	// 	})
	// }

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(JsonResponseLeaveApproved{
		Status:  200,
		Data:    []LeaveApproved{approved},
		Message: fmt.Sprintf("Approved leave successfully: %s", result.InsertedID),
	})
}

//this function is used to get the list of all students
func GetAllStudents(w http.ResponseWriter, r *http.Request) {
	var students []Student
	cursor, err := studentdb.Find(context.Background(), bson.M{})
	if err != nil {
		json.NewEncoder(w).Encode(JsonResponseStudent{
			Status:  400,
			Message: fmt.Sprintf("Unknown internal error: %v", err),
		})
		return
	}

	err = cursor.All(context.Background(), &students)
	if err != nil {
		json.NewEncoder(w).Encode(JsonResponseStudent{
			Status:  400,
			Message: fmt.Sprintf("Unknown internal error: %v", err),
		})
		return
	}

	res := JsonResponseStudent{
		Status:  200,
		Data:    students,
		Message: "listed leave requests successfully",
	}

	defer cursor.Close(context.Background())

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(&res)
}

//this is used to get the list of students who applied leave requests
func GetLeaveRequests(w http.ResponseWriter, r *http.Request) {
	var leaves []LeaveRequest
	cursor, err := leaverequestdb.Find(context.Background(), bson.M{})
	if err != nil {
		json.NewEncoder(w).Encode(JsonResponseLeaveRequest{
			Status:  400,
			Message: fmt.Sprintf("Unknown internal error: %v", err),
		})
		return
	}

	err = cursor.All(context.Background(), &leaves)
	if err != nil {
		json.NewEncoder(w).Encode(JsonResponseLeaveRequest{
			Status:  400,
			Message: fmt.Sprintf("Unknown internal error: %v", err),
		})
		return
	}

	res := JsonResponseLeaveRequest{
		Status:  200,
		Data:    leaves,
		Message: "listed leave requests successfully",
	}

	defer cursor.Close(context.Background())

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(&res)
}

//this function returns the list of students whose leaves got approved
func GetAllLeaveApproves(w http.ResponseWriter, r *http.Request) {
	var approves []LeaveApproved
	cursor, err := leaveapprovedb.Find(context.Background(), bson.M{})
	if err != nil {
		json.NewEncoder(w).Encode(JsonResponseLeaveApproved{
			Status:  400,
			Message: fmt.Sprintf("Unknown internal error: %v", err),
		})
		return
	}

	err = cursor.All(context.Background(), &approves)
	if err != nil {
		json.NewEncoder(w).Encode(JsonResponseLeaveApproved{
			Status:  400,
			Message: fmt.Sprintf("Unknown internal error: %v", err),
		})
		return
	}

	res := JsonResponseLeaveApproved{
		Status:  200,
		Data:    approves,
		Message: "leave approved successfully",
	}

	defer cursor.Close(context.Background())

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(&res)
}
