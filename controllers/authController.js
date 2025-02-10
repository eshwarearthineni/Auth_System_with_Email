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

    }
    catch(error){
        res.json({success: false, message: error.message})
    }
}