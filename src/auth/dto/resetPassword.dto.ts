import { IsNotEmpty, IsString, Matches, MaxLength, MinLength } from 'class-validator';
export class ResetPasswordDto {
    @IsString()
	@IsNotEmpty()
    email: string;

	@IsString()
	@IsNotEmpty()
	@MinLength(4)
    @MaxLength(20)
	@Matches(/((?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/, {message: 'password too weak'})
    password: string;

    @IsString()
	@IsNotEmpty()
    resetToken:string
}
