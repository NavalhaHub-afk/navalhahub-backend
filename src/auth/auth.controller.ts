import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Res,
  UnauthorizedException,
  UnprocessableEntityException,
  ConflictException,
} from '@nestjs/common';
import { Request, Response } from 'express';

import { AuthService } from './auth.service';
import { LoginEmailDto } from './dto/login-email.dto';
import { SignupEmailDto } from './dto/signup-email.dto';

@Controller('api/v1/auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  @HttpCode(HttpStatus.CREATED)
  async signup(
    @Body() dto: SignupEmailDto,
    @Res({ passthrough: true }) res?: Response,
  ) {
    return this.authService.signup(dto, res);
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() dto: LoginEmailDto,
    @Res({ passthrough: true }) res?: Response,
  ) {
    return this.authService.login(dto, res);
  }

  @Get('me')
  async getCurrentUser(@Req() req: Request) {
    return this.authService.getCurrentUser(req);
  }

  @Post('logout')
  @HttpCode(HttpStatus.NO_CONTENT)
  async logout(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    return this.authService.logout(req, res);
  }

  @Post('password/reset-request')
  @HttpCode(HttpStatus.OK)
  async requestPasswordReset(@Body() dto: { email: string }) {
    if (!dto?.email) {
      throw new BadRequestException({
        error: {
          code: 'BAD_REQUEST',
          message: 'Email é obrigatório',
          details: {},
        },
      });
    }

    return this.authService.requestPasswordReset(dto);
  }

  @Post('password/reset-confirm')
  @HttpCode(HttpStatus.OK)
  async confirmPasswordReset(
    @Body() dto: { token: string; newPassword: string },
  ) {
    if (!dto?.token || !dto?.newPassword) {
      throw new BadRequestException({
        error: {
          code: 'TOKEN_INVALID',
          message: 'Token ou nova senha inválidos',
          details: {},
        },
      });
    }

    return this.authService.confirmPasswordReset(dto);
  }
}
