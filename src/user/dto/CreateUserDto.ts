import { IsBoolean, IsNotEmpty, IsNumber, IsOptional, IsString } from 'class-validator';

export class CreateUserDto {
	@IsString()
	@IsNotEmpty()
	public name: string;

	@IsString()
	@IsNotEmpty()
	public username: string;


	@IsString()
	@IsNotEmpty()
	public email: string;

	// Validates for an integer
	@IsNumber() public age: number;

	// Validates for an integer
	@IsBoolean() public sex: boolean;

	@IsString()
	@IsNotEmpty()
	public password: string;

	@IsOptional()
	public refreshToken: string;
}
