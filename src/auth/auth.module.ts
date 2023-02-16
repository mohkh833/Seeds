import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { PrismaModule } from 'src/prisma/prisma.module';
import { JwtModule } from '@nestjs/jwt';
import { AccessTokenStrategy } from './strategies/accessToken.strategy';
import { RefreshTokenStrategy } from './strategies/refreshToken.strategy';
import { UserModule } from 'src/user/user.module';
import { AuthRepository } from './repositories/auth.repository';
import { EmailModule } from 'src/email/email.module';

@Module({
  imports: [PrismaModule,JwtModule.register({}), UserModule, EmailModule],
  controllers: [AuthController],
  providers: [AuthService, AccessTokenStrategy, RefreshTokenStrategy,AuthRepository],

})
export class AuthModule {}
