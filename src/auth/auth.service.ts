import { BadRequestException, ForbiddenException, Injectable } from '@nestjs/common';
import { CreateUserDto } from 'src/user/dto/CreateUserDto';
import { UserService } from 'src/user/user.service';
import * as argon2 from 'argon2';
import { JwtService } from '@nestjs/jwt';
import { AuthDto } from './dto/auth.dto';

@Injectable()
export class AuthService {
	constructor(private usersService: UserService, private jwtService: JwtService) {}

	async signUp(createUserDto: CreateUserDto): Promise<any> {
		// check if user exists
		const userExists = await this.usersService.findByUserName(createUserDto.username);

		if (userExists) throw new BadRequestException('User already exists');

		// Hash Password
		const hash = await this.hashData(createUserDto.password);
		const newUser = await this.usersService.createUser({
			...createUserDto,
			password: hash
		});

		const tokens = await this.getTokens(newUser.id, newUser.username);
		await this.updateRefreshToken(newUser.id, tokens.refreshToken);
		return tokens;
	}

	async signIn(data: AuthDto) {
		const user = await this.usersService.findByUserName(data.username);

		if (!user) throw new BadRequestException('User does not exist ');

		const passwordMatches = await argon2.verify(user.password, data.password);

		if (!passwordMatches) throw new BadRequestException('Password is incorrect');

		const tokens = await this.getTokens(user.id, user.username);

		await this.updateRefreshToken(user.id, tokens.refreshToken);

		return tokens;
	}

	async logOut(userId: number) {
		return this.usersService.update(userId, { refreshToken: '' });
	}

	hashData(data: string) {
		return argon2.hash(data);
	}

	async updateRefreshToken(userId: number, refreshToken: string) {
		const hashedRefreshToken = await this.hashData(refreshToken);
		await this.usersService.update(userId, {
			refreshToken: hashedRefreshToken
		});
	}

	async getTokens(userId: number, username: string) {
		const [ accessToken, refreshToken ] = await Promise.all([
			this.jwtService.signAsync(
				{
					sub: userId,
					username
				},
				{
					secret: process.env.JWT_ACCESS_SECRET,
					expiresIn: '15m'
				}
			),
			this.jwtService.signAsync(
				{
					sub: userId,
					username
				},
				{
					secret: process.env.JWT_REFRESH_SECRET,
					expiresIn: '7d'
				}
			)
		]);

		return {
			accessToken,
			refreshToken
		};
	}

	async refreshTokens(userId: number, refreshToken: string) {
		const user = await this.usersService.findById(userId);
		if (!user || !user.refreshToken) throw new ForbiddenException('Access Denied');

		const refreshTokenMatches = await argon2.verify(user.refreshToken, refreshToken);

		if (!refreshTokenMatches) throw new ForbiddenException('Access Denied');

		const tokens = await this.getTokens(user.id, user.username);

		await this.updateRefreshToken(user.id, tokens.refreshToken);

		return tokens;
	}
}
