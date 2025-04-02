import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { LoginUserDto, RegisterUserDto } from './dto';
import { RpcException } from '@nestjs/microservices';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger('AuthService');
  constructor(private readonly jwtService: JwtService) {
    super();
  }
  onModuleInit() {
    this.$connect();
    this.logger.log('MongoDb Connected');
  }

  async signJWT(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }

  async registerUser(registerUserDto: RegisterUserDto) {
    this.logger.log('registerUser');
    const { email, password, name } = registerUserDto;
    try {
      const user = await this.user.findUnique({ where: { email } });
      if (user) {
        throw new RpcException({
          status: 400,
          message: 'User already exists',
        });
      }
      const newUser = await this.user.create({
        data: {
          name,
          email,
          password: bcrypt.hashSync(password, 10),
        },
      });

      const { password: __, ...rest } = newUser;

      return {
        user: rest,
        token: await this.signJWT({
          id: newUser.id,
          email: newUser.email,
          name: newUser.name,
        }),
      };
    } catch (error) {
      throw new RpcException({
        status: 500,
        message: error.message,
      });
    }
  }

  async loginUser(loginUserDto: LoginUserDto) {
    this.logger.log('loginUser');
    const { email, password } = loginUserDto;
    try {
      const user = await this.user.findUnique({ where: { email } });
      if (!user) {
        throw new RpcException({
          status: 400,
          message: 'User not found',
        });
      }
      const isPasswordCorrect = bcrypt.compare(password, user.password);
      if (!isPasswordCorrect) {
        throw new RpcException({
          status: 400,
          message: 'Incorrect password',
        });
      }
      const { password: __, ...rest } = user;
      return {
        user: rest,
        token: await this.signJWT({
          id: user.id,
          email: user.email,
          name: user.name,
        }),
      };
    } catch (error) {
      throw new RpcException({
        status: 500,
        message: error.message,
      });
    }
  }

  async veryfyToken(token: string) {
    this.logger.log('veryfyToken');
    console.log('token', token);
    try {
      const { sub, iat, exp, ...user } = this.jwtService.verify(token);
      console.log('user', user);
      return {
        user,
        token: await this.signJWT(user),
      };
    } catch (error) {
      throw new RpcException({
        status: 401,
        message: 'Invalid token',
      });
    }
  }
}
