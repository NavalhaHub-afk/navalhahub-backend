import {
  Body,
  Controller,
  Post,
  BadRequestException,
} from '@nestjs/common';

import { AuthService } from './auth.service';

import { SignupEmailDto } from './dto/signup-email.dto';
import { LoginEmailDto } from './dto/login-email.dto';
import {
  RequestEmailOtpDto,
  RequestPhoneOtpDto,
} from './dto/request-otp.dto';
import { VerifyOtpDto } from './dto/verify-otp.dto';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
  ) {}

  /**
   * Cadastro com email e senha
   *
   * POST /auth/signup/email
   */
  @Post('signup/email')
  async signupWithEmail(
    @Body() dto: SignupEmailDto,
  ) {
    return this.authService.signupWithEmail(
      dto.email,
      dto.password,
    );
  }

  /**
   * Login com email e senha
   *
   * POST /auth/login/email
   */
  @Post('login/email')
  async loginWithEmail(
    @Body() dto: LoginEmailDto,
  ) {
    return this.authService.loginWithEmail(
      dto.email,
      dto.password,
    );
  }

  /**
   * Solicita OTP por email
   *
   * POST /auth/otp/email/request
   */
  @Post('otp/email/request')
  async requestEmailOtp(
    @Body() dto: RequestEmailOtpDto,
  ) {
    return this.authService.requestEmailOtp(
      dto.email,
    );
  }

  /**
   * Solicita OTP por telefone
   *
   * POST /auth/otp/phone/request
   */
  @Post('otp/phone/request')
  async requestPhoneOtp(
    @Body() dto: RequestPhoneOtpDto,
  ) {
    return this.authService.requestPhoneOtp(
      dto.phone,
    );
  }

  /**
   * Verifica OTP de email ou telefone
   *
   * POST /auth/otp/verify
   */
  @Post('otp/verify')
  async verifyOtp(
    @Body() dto: VerifyOtpDto,
  ) {
    if (dto.type === 'email') {
      if (!dto.email) {
        throw new BadRequestException(
          'Email é obrigatório para verificar OTP de email',
        );
      }

      return this.authService.verifyEmailOtp(
        dto.email,
        dto.token,
      );
    }

    if (!dto.phone) {
      throw new BadRequestException(
        'Telefone é obrigatório para verificar OTP de telefone',
      );
    }

    return this.authService.verifyPhoneOtp(
      dto.phone,
      dto.token,
    );
  }
}
