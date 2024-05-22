package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	jwtware "github.com/gofiber/jwt/v2"
	"github.com/jmoiron/sqlx"
	"golang.org/x/crypto/bcrypt"
	"strconv"
	"time"
)

var db *sqlx.DB

const jwtSecret = "secret"

func main() {
	var err error
	db, err = sqlx.Open("mysql", "root:password@tcp(localhost:3306)/test")
	if err != nil {
		panic(err)
	}

	app := fiber.New()
	app.Use("/hello", jwtware.New(jwtware.Config{
		SigningMethod: "HS256",
		SigningKey:    []byte(jwtSecret),
		SuccessHandler: func(c *fiber.Ctx) error {
			return c.Next()
		},
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			return fiber.ErrUnauthorized
		},
	}))

	app.Post("/signup", Signup)
	app.Post("login", Login)
	app.Get("/hello", Hello)

	app.Listen(":8000")
}

func Signup(c *fiber.Ctx) error {
	request := SignupRequest{}
	err := c.BodyParser(&request)
	if err != nil {
		return err
	}

	if request.Username == "" || request.Password == "" {
		return fiber.ErrUnprocessableEntity
	}

	password, err := bcrypt.GenerateFromPassword([]byte(request.Password), 10)
	if err != nil {
		return fiber.NewError(fiber.StatusUnprocessableEntity, err.Error())
	}

	query := "insert user (username, password) values (?, ?)"
	result, err := db.Exec(query, request.Username, string(password))
	if err != nil {
		return fiber.NewError(fiber.StatusUnprocessableEntity, err.Error())
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fiber.NewError(fiber.StatusUnprocessableEntity, err.Error())
	}

	user := User{
		ID:       int(id),
		Username: request.Username,
		Password: string(password),
	}

	return c.Status(fiber.StatusCreated).JSON(user)
}

func Login(c *fiber.Ctx) error {
	request := LoginRequest{}
	err := c.BodyParser(&request)
	if err != nil {
		return err
	}

	if request.Username == "" || request.Password == "" {
		return fiber.ErrUnprocessableEntity
	}

	user := User{}
	query := "select id, username, password from user where username = ?"
	err = db.Get(&user, query, request.Username)
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, "Incorrect username or password")
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(request.Password))
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, "Incorrect username or password")
	}

	cliams := jwt.StandardClaims{
		Issuer:    strconv.Itoa(user.ID),
		ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, cliams)
	token, err := jwtToken.SignedString([]byte(jwtSecret))
	if err != nil {
		return fiber.ErrInternalServerError
	}

	return c.JSON(fiber.Map{
		"jwtToken": token,
	})
}

func Hello(c *fiber.Ctx) error {
	return c.SendString("Hello, World!")
}

type User struct {
	ID       int    `db:"id" json:"id"`
	Username string `db:"username" json:"username"`
	Password string `db:"password" json:"password"`
}

type SignupRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func Fiber() {
	// app := http.NewServeMux() // need to handle many thing by myself
	// app := mux.NewRouter() // simplify net/http
	app := fiber.New(fiber.Config{
		// use fiber.Config to config
		Prefork: true,
		// it will spawn multiple go processes listening on the same port
	})

	// middleware
	app.Use("/hello", func(c *fiber.Ctx) error {
		c.Locals("name", "oat")
		// if not specific path it will apply to all path
		fmt.Println("before")
		err := c.Next() // err from handler
		fmt.Println("after")
		return err
	})

	// request id middleware
	app.Use(requestid.New())
	// cors middleware
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowMethods: "*",
		AllowHeaders: "*",
	}))
	// logger middleware
	app.Use(logger.New(logger.Config{
		TimeZone: "Asia/Bangkok",
	}))

	// app.HandleFunc("/hello/{id}", Hello).Methods(http.MethodGet)
	app.Get("/hello", func(c *fiber.Ctx) error {
		// methods in context return error
		name := c.Locals("name") // receive name from middleware

		return c.SendString(fmt.Sprintf("GET: Hello %v", name))
	})
	app.Post("/hello", func(c *fiber.Ctx) error {
		return c.SendString("POST: Hello")
	})
	// parameters
	// optional when use ? ex. :surname?
	app.Get("/hello/:name/:surname", func(c *fiber.Ctx) error {
		name := c.Params("name")
		surname := c.Params("surname")

		return c.SendString("name: " + name + ", surname: " + surname)
	})
	// int parameters
	app.Get("/hello/:id", func(c *fiber.Ctx) error {
		id, err := c.ParamsInt("id") // return int, err
		if err != nil {
			return fiber.ErrBadRequest
		}

		return c.SendString(fmt.Sprintf("ID = %v", id))
	})
	// query
	app.Get("/query", func(c *fiber.Ctx) error {
		// localhost:8000/query?name=oat&surname=montheankul
		name := c.Query("name")
		surname := c.Query("surname")

		return c.SendString("name: " + name + ", surname: " + surname)
	})
	app.Get("/query2", func(c *fiber.Ctx) error {
		person := Person{}
		c.QueryParser(&person) // map query param with struct

		return c.JSON(person)
	})
	// wildcards
	app.Get("/wildcards/*", func(c *fiber.Ctx) error {
		wildcard := c.Params("*")
		return c.SendString(wildcard)
	})
	// static file
	app.Static("/", "./www-root", fiber.Static{
		// can add config for static file
		Index:         "index.html",
		CacheDuration: time.Second * 10, // caching
	})
	// new error
	app.Get("/error", func(c *fiber.Ctx) error {
		return fiber.NewError(fiber.StatusNotFound, "content not found")
	})

	// group
	v1 := app.Group("/v1", func(c *fiber.Ctx) error { // can use middleware on group
		c.Set("Version", "v1") // set header

		return c.Next()
	})
	v1.Get("/hello", func(c *fiber.Ctx) error {
		return c.SendString("Hello v1")
	})

	v2 := app.Group("/v2", func(c *fiber.Ctx) error {
		c.Set("Version", "v2")
		// c.Get use to get header
		return c.Next()
	})
	v2.Get("/hello", func(c *fiber.Ctx) error {
		return c.SendString("Hello v2")
	})

	// mount : similar as group
	userApp := fiber.New()
	userApp.Get("/login", func(c *fiber.Ctx) error {
		return c.SendString("Login")
	})

	// localhost:8000/user/login
	app.Mount("/user", userApp)

	// server
	app.Server().MaxConnsPerIP = 1
	app.Get("/server", func(c *fiber.Ctx) error {
		time.Sleep(time.Second * 30)
		return c.SendString("server")
	})

	app.Get("/env", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"BaseURL":     c.BaseURL(),
			"Hostname":    c.Hostname(),
			"IP":          c.IP(),
			"IPs":         c.IPs(), // if you use proxy/ forward port, ..
			"OriginalURL": c.OriginalURL(),
			"Path":        c.Path(),
			"Protocol":    c.Protocol(),
			"Sub-domain":  c.Subdomains(),
		})
	})

	// body
	app.Post("/body", func(c *fiber.Ctx) error {
		// fmt.Printf("IsJson: %v\n", c.Is("json")) // check body is json? it will check from header
		// fmt.Println(string(c.Body()))            // c.Body return slice of bytes
		person := Person{}
		err := c.BodyParser(&person) // it will automatically check content type and parse to this type
		// c.BodyParser will check type form content type like c.Is
		if err != nil {
			return err
			// it will return fiber.NewError(fiber.StatusUnprocessableEntity) when can't parse this content
		}

		fmt.Println(person)
		return nil
	})

	app.Post("/body2", func(c *fiber.Ctx) error {
		data := map[string]interface{}{} // use if request is not tight
		err := c.BodyParser(&data)
		if err != nil {
			return err
		}

		fmt.Println(data)
		return nil
	})

	// http.ListenAndServe(":8080", app)
	app.Listen(":8000")
}

/*
func Hello(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	fmt.Println(id)
}
*/

type Person struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}
