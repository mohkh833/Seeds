import { Controller, ValidationPipe, Post, Body, Get, Req, UseGuards, Res } from '@nestjs/common';
import { Request, Response } from 'express';
import { CreateUserDto } from 'src/user/dto/CreateUserDto';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/auth.dto';
import { AccessTokenGuard } from 'src/common/guards/accessToken.guard';
import { RefreshTokenGuard } from 'src/common/guards/refreshToken.guard';
import { ResetPasswordDto } from './dto/resetPassword.dto';
import { GoogleOauthGuard } from './guards/google-oauth.guard';

@Controller('auth')
export class AuthController {
	constructor(private authService: AuthService) {}

	@Post('signup')
	async signup(@Body(ValidationPipe) createUserDto: CreateUserDto, @Res()res:Response) {
		const response = await this.authService.signUp(createUserDto);
		return res.status(response.status).json(response)
	}

	@Post('signin')
	async signin(@Body(ValidationPipe) data: AuthDto, @Res()res:Response) {
		const response = await this.authService.signIn(data);
		return res.status(response.status).json(response)
	}

	@UseGuards(AccessTokenGuard)
	@Get('logout')
	async logout(@Req() req: Request) {
		this.authService.logOut(req.user['sub']);
	}

	@UseGuards(RefreshTokenGuard)
	@Get('refresh')
	async refreshTokens(@Req() req: Request, @Res()res:Response) {
		const userId = req.user['sub'];
		const refreshToken = req.user['refreshToken'];
		const response = await this.authService.refreshTokens(userId, refreshToken);
		return res.status(response.status).json(response)
	}

	@Post('forget-password')
	forgetPassword(@Body() data ){
		return this.authService.sendPasswordResetToken(data.email)
	}

	@Post('reset-password')
	resetPassword(@Body(ValidationPipe) data:ResetPasswordDto ){
		return this.authService.resetPassword(data)
	}

	@Get('google')
	@UseGuards(GoogleOauthGuard)
	// eslint-disable-next-line @typescript-eslint/no-empty-function
	async auth() {}

	@Get('google/callback')
	@UseGuards(GoogleOauthGuard)
	async googleAuthCallback(@Req() req, @Res()res:Response) {
		const response = await this.authService.googleSignIn(req.user);
		res.cookie('accessToken',response.data[0].accessToken, {
			maxAge: 2592000000,
			sameSite: true,
			secure: false,
		})
		return res.status(200).json(response)
	}
}
