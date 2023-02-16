import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer'
import { SendEmailDto } from './dto/SendEmailDto';
import { EmailRepository } from './email.repository';
@Injectable()
export class EmailService {
    constructor(private emailRepository:EmailRepository){}
    
    async sendMail(sendEmailDto:SendEmailDto) : Promise<void> {
        this.emailRepository.sendMail(sendEmailDto)
    }
}
