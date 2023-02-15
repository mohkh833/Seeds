import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { User, Prisma } from '@prisma/client';
import { CreateUserDto } from './dto/CreateUserDto';
import { UpdateUserDto } from './dto/UpdateUserDto';
import { UserRepository } from '../user/repositories/user.repository';
@Injectable()
export class UserService {
	constructor(private prisma: PrismaService, private userRepository: UserRepository) {}

	async createUser(data: CreateUserDto): Promise<User> {
		return this.userRepository.createUser(data);
	}

	async findAll(): Promise<User[]> {
		return this.userRepository.findAll();
	}

	async findById(id: number): Promise<User> {
		return this.userRepository.findById(id);
	}

	async findByUserName(username: string): Promise<User> {
		return this.userRepository.findByUserName(username);
	}

	async remove(id: number): Promise<User> {
		return this.userRepository.remove(id);
	}

	async update(id: number, updateUserDto: UpdateUserDto): Promise<User> {
		return this.userRepository.update(id, updateUserDto);
	}
}
