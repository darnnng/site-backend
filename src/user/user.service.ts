import { ConflictException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma.service';
import { CreateUserDto } from './dto/user.dto';
import { hash } from 'bcrypt';

@Injectable()
export class UserService {
  constructor(private prisma: PrismaService) {}

  async create(dto: CreateUserDto) {
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    if (user) throw new ConflictException('User already exists');

    const newUser = await this.prisma.user.create({
      data: {
        ...dto,
        password: await hash(dto.password, 10),
      },
    });

    const { password, ...createdUser } = newUser;

    return createdUser;
  }

  async findByEmail(userEmail: string) {
    return await this.prisma.user.findUnique({
      where: {
        email: userEmail,
      },
    });
  }

  async findById(userId: number) {
    const foundUser = await this.prisma.user.findUnique({
      where: {
        id: userId,
      },
    });

    const { password, ...user } = foundUser;

    return user;
  }
}
