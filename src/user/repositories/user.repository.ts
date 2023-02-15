import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { User, Prisma } from '@prisma/client';
import { CreateUserDto } from '../dto/CreateUserDto';
import { UpdateUserDto } from '../dto/UpdateUserDto';
@Injectable()
export class UserRepository  {
    constructor(private prisma: PrismaService) {}

    async createUser(data:CreateUserDto) : Promise<User> {
        return this.prisma.user.create({
            data
        })
    }

    async findAll(): Promise<User[]> {
        return this.prisma.user.findMany();
    }

    async findById(id:number) : Promise<User> {
        return this.prisma.user.findFirst({
            where:{
                id:id
            }
        })
    }

    async findByUserName(username: string) : Promise<User> {
        return this.prisma.user.findFirst({
            where:{
                username:username
            }
        })
    }

    async remove(id:number) : Promise<User> {
        return this.prisma.user.delete({
            where:{
                id:id
            }
        })
    }

    async update(
        id: number,
        updateUserDto: UpdateUserDto,
      ): Promise<User> {
        return this.prisma.user.update({
            where:{
                id:id
            },
            data:updateUserDto
            
        })

    }
}
