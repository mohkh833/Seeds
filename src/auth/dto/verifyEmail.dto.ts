import { IsNotEmpty, IsString } from 'class-validator';
export class VerifyEmailDto {
    @IsString()
	@IsNotEmpty()
    email: string;

    @IsString()
	@IsNotEmpty()
    verifyToken:string
}
