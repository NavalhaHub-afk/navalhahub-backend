import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Headers,
  HttpCode,
  HttpStatus,
  Post,
} from '@nestjs/common';

import { AuthService } from './auth.service';
import { LoginEmailDto } from './dto/login-email.dto';
import {
  PasswordResetConfirmDto,
  PasswordResetRequestDto,
} from './dto/password-reset.dto';
import { SignupEmailDto } from './dto/signup-email.dto';

@Controller('api/v1/auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  @HttpCode(HttpStatus.CREATED)
  async signup(@Body() dto: SignupEmailDto) {
    return this.authService.signup(dto);
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(@Body() dto: LoginEmailDto) {
    return this.authService.login(dto);
  }

  @Get('me')
  async getCurrentUser(
    @Headers('authorization') authorization?: string,
  ) {
    return this.authService.getCurrentUser(authorization);
  }

  @Post('logout')
  @HttpCode(HttpStatus.NO_CONTENT)
  async logout(
    @Headers('authorization') authorization?: string,
  ) {
    return this.authService.logout();
  }

  @Post('password/reset-request')
  @HttpCode(HttpStatus.OK)
  async requestPasswordReset(@Body() dto: PasswordResetRequestDto) {
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
    @Body() dto: PasswordResetConfirmDto,
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
