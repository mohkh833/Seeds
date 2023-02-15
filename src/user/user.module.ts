import { Module } from '@nestjs/common';
import { UserRepository } from 'src/user/repositories/user.repository';
import { PrismaModule } from 'src/prisma/prisma.module';
import { UserController } from './user.controller';
import { UserService } from './user.service';

@Module({
  imports:[PrismaModule],
  controllers: [UserController],
  providers: [UserService, UserRepository],
  exports:[UserService]
})
export class UserModule {}
