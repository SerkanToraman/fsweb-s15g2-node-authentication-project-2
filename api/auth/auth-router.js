const router = require("express").Router();
const { usernameVarmi, rolAdiGecerlimi,checkPayload,generateToken } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // bu secret'ı kullanın!
const jwt = require("jsonwebtoken");
const bcrypt = require('bcryptjs');
const userModel = require("../users/users-model")


router.post("/register", rolAdiGecerlimi, async (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status: 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
    try {
      const insertedUserData ={
        username:req.body.username,
        password:req.body.password,
        role_name:req.body.role_name,
      }
      insertedUserData.password = bcrypt.hashSync(insertedUserData.password,2);
      const insertedUser = await userModel.ekle(insertedUserData);
      res.status(201).json(
        insertedUser
      );
      
    } catch (error) {
      next(error)
    }
});


router.post("/login",checkPayload, usernameVarmi, async (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status: 200
    {
      "message": "sue geri geldi!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    Token 1 gün sonra timeout olmalıdır ve aşağıdaki bilgiyi payloadında içermelidir:

    {
      "subject"  : 1       // giriş yapan kullanıcının user_id'si
      "username" : "bob"   // giriş yapan kullanıcının username'i
      "role_name": "admin" // giriş yapan kulanıcının role adı
    }
   */
  try {  
      const payload = {
      subject: req.userData.user_id,
      username: req.userData.username,
      role_name: req.userData.role_name
  }
  const token = jwt.sign(payload,JWT_SECRET,{expiresIn:"24h"});
  res.json({message: `${req.userData.username} geri geldi!`,
  token:token})  
  } catch (error) {
    next(error)
  }

});


module.exports = router;
