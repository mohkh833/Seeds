import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer'
import { SendEmailDto } from './dto/SendEmailDto';
@Injectable()
export class EmailRepository {
    async sendMail(sendEmailDto:SendEmailDto) : Promise<void> {
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth:{
                user:process.env.EMAIL,
                pass: process.env.GMAIL_PASS,
            }
        })
        
        const mailOptions = {
            from: process.env.EMAIL,
            ...sendEmailDto
        }

        await transporter.sendMail(mailOptions);
    }
}
