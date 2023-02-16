import { Controller, ValidationPipe, Post, Body, Get, Req, UseGuards } from '@nestjs/common';
import { Request } from 'express';
import { CreateUserDto } from 'src/user/dto/CreateUserDto';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/auth.dto';
import { AccessTokenGuard } from 'src/common/guards/accessToken.guard';
import { RefreshTokenGuard } from 'src/common/guards/refreshToken.guard';
import { ResetPasswordDto } from './dto/resetPassword.dto';

@Controller('auth')
export class AuthController {
	constructor(private authService: AuthService) {}

	@Post('signup')
	signup(@Body(ValidationPipe) createUserDto: CreateUserDto) {
		
		return this.authService.signUp(createUserDto);
	}

	@Post('signin')
	signin(@Body(ValidationPipe) data: AuthDto) {
		return this.authService.signIn(data);
	}

	@UseGuards(AccessTokenGuard)
	@Get('logout')
	logout(@Req() req: Request) {
		this.authService.logOut(req.user['sub']);
	}

	@UseGuards(RefreshTokenGuard)
	@Get('refresh')
	refreshTokens(@Req() req: Request) {
		const userId = req.user['sub'];
		const refreshToken = req.user['refreshToken'];
		return this.authService.refreshTokens(userId, refreshToken);
	}

	@Post('forget-password')
	forgetPassword(@Body() data ){
		return  this.authService.sendPasswordResetToken(data.email)

	}

	@Post('reset-password')
	resetPassword(@Body(ValidationPipe) data:ResetPasswordDto ){
		return this.authService.resetPassword(data)
	}
}
