const { JWT_SECRET } = require("../secrets"); // bu secreti kullanın!
const userModel = require('../users/users-model')
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const sinirli = (req, res, next) => {
  /*
    Eğer Authorization header'ında bir token sağlanmamışsa:
    status: 401
    {
      "message": "Token gereklidir"
    }

    Eğer token doğrulanamıyorsa:
    status: 401
    {
      "message": "Token gecersizdir"
    }

    Alt akıştaki middlewarelar için hayatı kolaylaştırmak için kodu çözülmüş tokeni req nesnesine koyun!
  */
 try {
  const token= req.headers.authotization;
  if(token){
      jwt.verify(token,JWT_SECRET,(err,decodedJWT)=>{
        if(err){
          next({status:401,message:"Token gecersizdir"})
        }else{
          req.decodedJWT=decodedJWT
          next()
        }
      })
  }else{
    res.status(401).json({message: "Token gereklidir"})
  }
 } catch (error) {
    next(error)
 }
 
}

const sadece = role_name => (req, res, next) => {
  /*
    
	Kullanıcı, Authorization headerında, kendi payloadu içinde bu fonksiyona bağımsız değişken olarak iletilen 
	rol_adı ile eşleşen bir role_name ile bir token sağlamazsa:
    status: 403
    {
      "message": "Bu, senin için değil"
    }

    Tekrar authorize etmekten kaçınmak için kodu çözülmüş tokeni req nesnesinden çekin!
  */try {
    if(req.decodedJWT && req.decodedJWT.role_name===role_name){
      next()
    }else{
      res.status(403).json({message: "Bu, senin için değil"})
    }
    
  } catch (error) {
    next(error)
  } 
}


const usernameVarmi = async (req, res, next) => {
  /*
    req.body de verilen username veritabanında yoksa
    status: 401
    {
      "message": "Geçersiz kriter"
    }
  */
  //step 1 : User is checked first
  const userIsExist = await userModel.goreBul({username:req.body.username}); // bir array gonderir
  // step 2 : passwordcheck
  if(userIsExist&&userIsExist.length>0){
      const user = userIsExist[0];
      if(bcrypt.compareSync(req.body.password, user.password)){

        req.userData=user;
        next();
      }else{
        res.status(401).json({message:'Geçersiz kriter'})
      }
      }else{
      res.status(401).json({
        "message": "Geçersiz kriter"
      });
    }
}


const rolAdiGecerlimi = async (req, res, next) => {
  /*
    Bodydeki role_name geçerliyse, req.role_name öğesini trimleyin ve devam edin.

    Req.body'de role_name eksikse veya trimden sonra sadece boş bir string kaldıysa,
    req.role_name öğesini "student" olarak ayarlayın ve isteğin devam etmesine izin verin.

    Stringi trimledikten sonra kalan role_name 'admin' ise:
    status: 422
    {
      "message": "Rol adı admin olamaz"
    }

    Trimden sonra rol adı 32 karakterden fazlaysa:
    status: 422
    {
      "message": "rol adı 32 karakterden fazla olamaz"
    }
  */
    try {
      let {role_name}= req.body;
      if(role_name){
        role_name = role_name.trim();
        if(role_name==="admin"){
          res.status(422).json({message:"Rol adı admin olamaz"})
        }else if(role_name.length>32){
          res.status(422).json({message:"rol adı 32 karakterden fazla olamaz"})
        }else{
          req.body.role_name = role_name
          next();
        }
      }else{
        req.body.role_name ="student"
      }

      // const roleNameIsExist = await userModel.goreBul({role_name:req.body.role_name});
      // if(roleNameIsExist&&roleNameIsExist.length>0){
      //   req.role_name=roleNameIsExist[0].role_name.trim();
      // }else if(!roleNameIsExist||req.role_name==""){
      //   req.role_name="student"
      // }

      // if(req.role_name==="admin"){
      //   res.status(422).json({message: "Rol adı admin olamaz"})
      // }else if(req.role_name.length<32){
      //   res.status(422).json({message: "rol adı 32 karakterden fazla olamaz"})
      // }else{
      //   next()
      // }
      

    } catch (error) {
      next(error)
    }
}
const checkPayload = (req,res,next)=>{
  try {
    let {username,password} = req.body;
    if(!username || !password){
      res.status(400).json({messsage:"Eksik alan var"});
    }else{
      next();
    }
  } catch (error) {
    next(error);
  }
}

function generateToken(user){
  const payload = {
      subject: user.user_id,
      usename: user.usename,
      role_name: user.role_name
  }
  const options = {
      expiresIn: "1d"
  }
  const token = jwt.sign(payload, JWT_SECRET, options);
  return token;
}



module.exports = {
  sinirli,
  usernameVarmi,
  rolAdiGecerlimi,
  sadece,
  checkPayload,
  generateToken
}
