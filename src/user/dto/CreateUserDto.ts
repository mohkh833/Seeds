import { IsBoolean, IsNotEmpty, IsNumber, IsOptional, IsString, Matches, MinLength, MaxLength, IsEmail } from 'class-validator';

export class CreateUserDto {
	@IsString()
	@IsNotEmpty()
	public name: string;

	@IsString()
	@IsNotEmpty()
	@MinLength(4)
    @MaxLength(20)
	public username: string;


	@IsString()
	@IsEmail()
	@IsNotEmpty()
	public email: string;

	// Validates for an integer
	@IsOptional()
	@IsNumber() public age: number;

	// Validates for an integer
	@IsOptional()
	@IsBoolean() public sex: boolean;

	@IsString()
	@IsNotEmpty()
	@MinLength(4)
    @MaxLength(20)
	@Matches(/((?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/, {message: 'password too weak'})
	public password: string;

	@IsOptional()
	public refreshToken: string;

	@IsOptional()
	public verifyToken: string;

	@IsOptional()
	public resetToken: string;

	@IsOptional()
	public resetTokenExpiry: Date;

	@IsOptional()
	public isVerified:boolean
}
