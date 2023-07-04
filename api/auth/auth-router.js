const router = require("express").Router();
const { usernameVarmi, rolAdiGecerlimi } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // bu secret'ı kullanın!
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


router.post("/login", usernameVarmi, (req, res, next) => {
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
});

module.exports = router;
