const express = require('express');
// const prisma = require('./config/db.config');
const bodyParser = require('body-parser')
const cors = require('cors')
require('dotenv/config');
const crypto = require('crypto');
const {PrismaClient}=require('@prisma/client')
const prisma = new PrismaClient()
const bcrypt = require('bcrypt');
const jwt=require('jsonwebtoken')
const app = express();
const port = process.env.PORT || 4001;

app.use(cors())
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));


const verifyToken=async (req,res,next)=>{
  
    const token=req.headers.authorization;
    if(!token){
        return res.status(401).send("Access denied")
    }
    try {
        const [type, tokenStr] = token.split(" ");
        if(type!=='Bearer')return res.status(401).send("Unauthorized request");
        if (tokenStr === null || !tokenStr) return res.status(401).send("Unauthorized request")
        const verifiedUser = jwt.verify(tokenStr, process.env.TOKEN_SECRET);
        if(!verifiedUser)return res.status(401).send("Unauthorized request")
        req.body.id=verifiedUser.payload.id;
        next()
    } catch (error) {
        return res.json(error)
    }
}
// app.use((req,res,next)=>{res.json({message:"Hello world"})})

app.post('/register',async (req, res) => {
try {
    const saltRounds = 10; // Salt rounds determine the complexity of the hashing

    const { email, password } = req.body;

    // Hash the password asynchronously
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Store the hashed password in the database
    const data = await prisma.admin.create({
        data: {
            email,
            password: hashedPassword // Store the hashed password, not the original password
        }
    });
    
  const  payload={
        id:data.id
    }

    const token=jwt.sign({payload},process.env.TOKEN_SECRET);

    // jwt sign function is used to create a token
    // 

    res.json({msg:'data retrived successfully',data,token});
} catch (error) {
    res.json(error);
}

})
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await prisma.admin.findUnique({
            where: {
                email
            }
        });

        if (!user) {
            // User not found
            return res.status(404).json({ error: 'User not found' });
        }

        // Compare the provided password with the hashed password from the database
        const match = await bcrypt.compare(password, user.password);

        if (!match) {
            // Passwords don't match
            return res.status(401).json({ error: 'Incorrect password' });
        }
        const token=jwt.sign({email},process.env.TOKEN_SECRET);

        // Passwords match, user authenticated successfully
        res.json({ msg: 'Login successful',token });

    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
});
app.get('/protected',verifyToken,async (req,res)=>{
    const id=req.body.user.id;
    const user=await prisma.admin.findUnique({
        where:{
            id
        }
    })

    if(user.isPremium){
        return res.json({msg:"You are a premium user"})
    }else
        {
        return res.json({msg:"You are not a premium user"})

        }

    return res.json({msg:req.body.user})
})
app.get('/users',verifyToken,async (req,res)=>{
   const id=req.body.id
    const user=await prisma.admin.findUnique({
        where:{
            id
        }
    })
    return res.json({msg:'success',user})
})



// Generate a random 256-bit (32-byte) key
// const secretKey = crypto.randomBytes(32).toString('hex');

// console.log('Generated JWT Secret Key:', secretKey);






app.listen(port, console.log(`app running on port ${port}`))