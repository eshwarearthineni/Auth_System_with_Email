import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import userModel from "../config/usermodel.js";

export const register = async(req, res){
    const {name, email, password} = req.body;

    if(!name, !email, !password){
        return res.status(400).json({message: "Please fill in all fields"});
    }
    try{
        const existingUser = await userModel.findOne({email})

        if(existingUser){
            return res.json({success: false, message:"User already exist"})
        }

        const hashedPassword = await bcrypt.hash(password, 10)

        const user = new userModel({name, email, password:hashedPassword});
        await user.save();

        const token = jwt.sign({id: user._id} , process.env.JWT_SECRET, {expiresIn:'7d'});

        res.cookie('token',token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'producton' ?
            'none':'strict',
            maxAge: 7*24*60*60*1000

        })

    }
    catch(error){
        res.json({success: false, message: error.message})
    }
}

export const login = async (req, res) =>{
    const {email, password} = req.body;

    if(!email || !password){
        return res.json({status: false, message: "Email and password are required"})
    }
    try{

    }catch(error){
        return res.json({success: false, message: error.message})
    }

}