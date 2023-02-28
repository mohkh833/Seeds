import { Injectable } from '@nestjs/common';
import { CreateUserDto } from 'src/user/dto/CreateUserDto';
import { AuthDto } from './dto/auth.dto';
import { ResetPasswordDto } from './dto/resetPassword.dto';
import { VerifyEmailDto } from './dto/verifyEmail.dto';
import { AuthRepository } from './repositories/auth.repository';

@Injectable()
export class AuthService {
	constructor(private authRepository: AuthRepository) {}

	async signUp(createUserDto: CreateUserDto){
		return this.authRepository.signUp(createUserDto)
	}

	async signIn(data: AuthDto) {
		return this.authRepository.signIn(data)
	}

	async logOut(userId: number) {
		return this.authRepository.logOut(userId)
	}

	async refreshTokens(userId: number, refreshToken: string) {
		return this.authRepository.refreshTokens(userId,refreshToken)
	}

	async sendPasswordResetToken(email:string) {
		return this.authRepository.sendEmail(email,'reset','https://example.com/reset?=','reset password email')
	}

	async resetPassword(data: ResetPasswordDto){
		return this.authRepository.resetPassword(data)
	}

	async verifyEmail(data:VerifyEmailDto){
		return this.authRepository.verifyEmail(data)
	}

	async resendVerifyToken(email:string){
		return this.authRepository.sendEmail(email,'verify','https://example.com/verify?=','Verification email')
	}
	
	async googleSignIn(user:any){
		return this.authRepository.googleSignIn(user)
	}
}
