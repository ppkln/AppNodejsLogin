const express = require("express");
const path = require("path");
const cookieSession = require("cookie-session");
const bcrypt = require("bcryptjs");
const dbConnection = require("./database");
const {body, validationResult} = require("express-validator");

const app = express();
app.use(express.urlencoded({extended:false}));
app.use(express.json())

app.set("views",path.join(__dirname,"views"))
app.set("view engine","ejs");
app.use(cookieSession({
    name:"session",
    keys:["key1","key2"],
    maxAge: 3600*1000 //มีอายุ 1 ชั่วโมง
}))

//Declare Middleware 
const IfNotLoggedIn = (req,res,next)=>{
    if(!req.session.isLoggedIn){
        return res.render('login-register')
    }
    next();
}
const IfLoggedIn = (req,res,next)=>{
    if(req.session.isLoggedIn){
        return res.redirect("/")
    }
    next();
}
//end of middleware
//root page
app.get("/", IfNotLoggedIn, (req,res,next)=>{
    dbConnection.execute("SELECT name FROM users WHERE id=?",[req.session.userID])
    .then(([rows])=>{
        res.render("home",{
            name:rows[0].name,
            idUser:req.session.userID,
            isLogged:req.session.isLoggedIn
        })
    })
})

// profile list
app.get("/profile-list",IfNotLoggedIn,(req,res)=>{
    dbConnection.execute("SELECT * FROM users")
    .then(([rows])=>{
        console.log("[rows] : "+[rows])
        res.render("profile-list",{
            profiles:rows,
            UserLoggedin:req.session.userName
        })
        
    })
})

//register
app.post("/register",IfLoggedIn,[
    body("user_email","invalid E-mail address").isEmail().custom((value)=>{
        return dbConnection.execute("SELECT email FROM users WHERE email=?",[value])
        .then(([rows])=>{
            if(rows.length > 0){
                return Promise.reject("This e-mail aleady in use!")
            }
            return true;
        })
    }),
    body("user_name","Name is not empty.").trim().not().isEmpty(),
    body("user_pass","The password must be minimum length 6 characters").trim().isLength({min:6})
],// end of post data validation
    (req,res,next)=>{
        const validation_result = validationResult(req);
        const {user_name, user_pass, user_email} = req.body;
        if(validation_result.isEmpty()){
            bcrypt.hash(user_pass,12).then((hash_pass)=>{
                dbConnection.execute("INSERT INTO users(name,email,password) VALUES(?,?,?)",[user_name,user_email,hash_pass])
                .then((resuly)=>{
                    res.send('สมัครสมาชิกใหม่สมบูรณ์, ตอนนี้ท่านสามารถทำการ Login ได้ <A href="/">Login</A>')
                }).catch(err=>{
                    if(err) throw err;
                })
            }).catch(err=>{
                if(err) throw err;
            })
        } else{
            let allErrors = validation_result.errors.map((error)=>{
                return error.msg;
            });
            res.render("login-register",{
                register_error:allErrors,
                old_data:req.body
            })
        }
    }
)
// to Edit Form
app.post("/editfrm",IfNotLoggedIn,(req,res)=>{
    console.log("อยู่ใน route /editfrm แบบ post")
    console.log("req.body.edit_id = "+req.body.edit_id);
    dbConnection.execute("SELECT * FROM users WHERE id=?",[req.body.edit_id])
    .then(([rows])=>{
        if (rows.length == 1){
            res.render("editfrm",{
                userid:rows[0].id,
                userEmail:rows[0].email,
                oldName:rows[0].name
            })
        } else {
            return Promise.reject("ไม่พบรหัสสมาชิกดังกล่างในฐานข้อมูล")
        }
    })
})

//edit user
app.post("/edit-profile",
(req,res)=>{
    const emailEdit = req.body.user_emailEdit;
    const nameEdit= req.body.user_nameEdit;
    console.log("อยู่ใน post[/edit-profile] แล้ว")
    console.log("req.body.user_emailEdit ="+emailEdit)
    console.log("req.body.user_nameEdit ="+nameEdit)
    dbConnection.execute("UPDATE users SET name = ? WHERE email=?",[nameEdit,emailEdit])
    .then(result=>{
        res.send('แก้ไขข้อมูลชื่อสมาชิกเรียบร้อยแล้ว, ตอนนี้ท่านสามารถกลับหน้า Profile List ได้ <A href="/profile-list">Profile List</A>')
    }).catch(err=>{
        if(err){
            if(err) throw err;
        }
    })
})

//Delete user
app.get("/delete/:id",(req,res)=>{
    const userTodelete = req.params.id;
    dbConnection.execute("DELETE FROM users WHERE id=?",[userTodelete])
    .then(([rows])=>{
        res.send('ลบข้อมูลชื่อสมาชิกเรียบร้อยแล้ว, ท่านสามารถกลับหน้า Profile List ได้ <A href="/profile-list">Profile List</A>')
    }).catch(err=>{
        if(err) throw err;
    })
})

//login
app.post("/", IfLoggedIn,[
    body("user_email").custom((value)=>{
        return dbConnection.execute("SELECT email FROM users WHERE email=?",[value])
        .then(([rows])=>{
            if(rows.length == 1){
                return true;
            }
            return Promise.reject("invalid email address!")
        })
    }),
    body("user_pass","Password is empty.").trim().not().isEmpty(),
],(req,res)=>{
    const validation_result=validationResult(req);
    const {user_email, user_pass} = req.body;
    if(validation_result.isEmpty()){
        dbConnection.execute("SELECT * FROM users WHERE email=?",[user_email])
        .then(([rows])=>{
            console.log("ค่า user_pass = "+user_pass);
            console.log("ค่า rows[0].password = "+rows[0].password);
            console.log("กำลัง bcrypt.compare-> password")
            bcrypt.compare(user_pass,rows[0].password).then(compare_result=>{
                console.log("ค่า compare_result:"+compare_result)
                if(compare_result===true){
                    req.session.isLoggedIn = true;
                    req.session.userID = rows[0].id;
                    req.session.userName = rows[0].name;
                    res.redirect("/")
                } else {
                    res.render("login-register",{
                        login_errors:["invalid Password (compare faile)"]
                    })
                }
            }).catch(err=>{
                if(err) throw err;
            })
        }).catch(err=>{
            if(err) throw err;
        })
    } else {
        let allErrors = validation_result.errors.map((error)=>{
            return error.msg;
        });

        res.render("login-register",{
            login_errors:allErrors
        })
    }
}
)


// logout
app.get("/logout",(req,res)=>{
    //destroy session
    req.session=null;
    res.redirect("/")
})

// page 404 
app.use("*",(req,res)=>{
    res.status(404).send("<h1>404 Page Not Found! </h1>")
})

app.listen(3000,()=>{console.log("Connect to server on port 3000.")});