import { Injectable, UnauthorizedException } from '@nestjs/common';
import { LoginDto } from './dto/auth.dto';
import { UserService } from 'src/user/user.service';
import { compare } from 'bcrypt';
import { JwtService } from '@nestjs/jwt';

const EXPIRE_TIME = 600000;

@Injectable()
export class AuthService {
  constructor(
    private userService: UserService,
    private jwtService: JwtService,
  ) {}

  async login(dto: LoginDto) {
    const user = await this.validateUser(dto);

    const payload = {
      email: user.email,
      sub: {
        firstName: user.firstName,
        lastName: user.lastName,
        occupation: user.occupation,
      },
    };

    return {
      user,
      tokens: {
        accessToken: await this.jwtService.signAsync(payload, {
          expiresIn: '1h',
          secret: process.env.JWT_SECRET,
        }),
        refreshToken: await this.jwtService.signAsync(payload, {
          expiresIn: '1d',
          secret: process.env.JWT_SECRET_REFRESH,
        }),
        expiresIn: new Date().setTime(
          new Date().getTime() + Number(process.env.TOKEN_LIFETIME),
        ),
      },
    };
  }

  async validateUser(dto: LoginDto) {
    const user = await this.userService.findByEmail(dto.email);

    if (user && (await compare(dto.password, user.password))) {
      const { password, ...currentUser } = user;
      return currentUser;
    }

    throw new UnauthorizedException('Email and/or password are/is not correct');
  }

  async refreshToken(user) {
    const payload = {
      email: user.email,
      sub: user.sub,
    };

    return {
      accessToken: await this.jwtService.signAsync(payload, {
        expiresIn: '1h',
        secret: process.env.JWT_SECRET,
      }),
      refreshToken: await this.jwtService.signAsync(payload, {
        expiresIn: '1d',
        secret: process.env.JWT_SECRET_REFRESH,
      }),
      expiresIn: new Date().setTime(
        new Date().getTime() + Number(process.env.TOKEN_LIFETIME),
      ),
    };
  }
}
