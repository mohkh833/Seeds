import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UserModule } from './user/user.module';
import { AuthModule } from './auth/auth.module';
import { PrismaModule } from './prisma/prisma.module';
import { RolesModule } from './roles/roles.module';

@Module({
  imports: [ConfigModule.forRoot(), UserModule, AuthModule, PrismaModule, RolesModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
