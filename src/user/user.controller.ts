import { Controller, Get, Post, Body, Delete, Param, UseGuards } from '@nestjs/common';
import { UserService } from './user.service';
import { CreateUserDto } from './dto/CreateUserDto';
import { AccessTokenGuard } from 'src/common/guards/accessToken.guard';

@Controller('user')
export class UserController {
    constructor(private readonly userService: UserService) {}

    @Post()
    create(@Body() createUserDto:CreateUserDto){
        return this.userService.createUser(createUserDto);
    }

    @Get()
    findAll(){
        return this.userService.findAll()
    }

    @Get(':id')
    findById(@Param('id') id: number) {
        return this.userService.findById(id)
    }

    @UseGuards(AccessTokenGuard)
    @Delete(':id')
    remove(@Param('id') id:number){
        return this.userService.remove(id)
    }
}
