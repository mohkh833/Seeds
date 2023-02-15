import { Injectable } from '@nestjs/common';
import { CreateUserDto } from 'src/user/dto/CreateUserDto';
import { AuthDto } from './dto/auth.dto';
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
}
