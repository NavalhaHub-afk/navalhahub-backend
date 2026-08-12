import {
  BadRequestException,
  ConflictException,
  Injectable,
  UnauthorizedException,
  UnprocessableEntityException,
} from '@nestjs/common';

import { LoginEmailDto } from './dto/login-email.dto';
import {
  PasswordResetConfirmDto,
  PasswordResetRequestDto,
} from './dto/password-reset.dto';
import { SignupEmailDto } from './dto/signup-email.dto';
import { SupabaseService } from '../supabase/supabase.service';

@Injectable()
export class AuthService {
  constructor(private readonly supabaseService: SupabaseService) { }

  async signup(dto: SignupEmailDto) {
    const supabase = this.supabaseService.getClient();
    const { data, error } = await supabase.auth.signUp({
      email: dto.email,
      password: dto.password,
      phone: dto.phone,
      options: {
        data: {
          full_name: dto.fullName,
        },
      },
    });

    if (error) {
      const message = String(error.message).toLowerCase();

      if (message.includes('already') || message.includes('registered')) {
        throw new ConflictException({
          error: {
            code: 'EMAIL_ALREADY_IN_USE',
            message: 'Este e-mail já está em uso',
            details: {},
          },
        });
      }

      if (message.includes('password') || message.includes('weak')) {
        throw new UnprocessableEntityException({
          error: {
            code: 'WEAK_PASSWORD',
            message: 'A senha informada não atende aos requisitos mínimos',
            details: {},
          },
        });
      }

      throw new BadRequestException({
        error: {
          code: 'BAD_REQUEST',
          message: error.message,
          details: {},
        },
      });
    }

    return {
      user: {
        id: data.user?.id ?? '',
        email: data.user?.email ?? dto.email,
      },
      requiresEmailVerification: !data.session,
    };
  }

  async login(dto: LoginEmailDto) {
    const supabase = this.supabaseService.getClient();
    const { data, error } = await supabase.auth.signInWithPassword({
      email: dto.email,
      password: dto.password,
    });

    if (error) {
      throw new UnauthorizedException({
        error: {
          code: 'INVALID_CREDENTIALS',
          message: 'Email ou senha inválidos',
          details: {},
        },
      });
    }

    return {
      user: {
        id: data.user?.id,
        email: data.user?.email,
      },
      session: {
        accessToken: data.session?.access_token,
        refreshToken: data.session?.refresh_token,
        expiresAt: data.session?.expires_at,
      },
    };
  }

  async getCurrentUser(authorization?: string) {
    if (
      typeof authorization !== 'string' ||
      !authorization.startsWith('Bearer ')
    ) {
      throw new UnauthorizedException({
        error: {
          code: 'UNAUTHORIZED',
          message: 'Sessão inválida ou expirada',
          details: {},
        },
      });
    }

    const token = authorization.substring(7);

    const supabase = this.supabaseService.getClient();

    const { data, error } = await supabase.auth.getUser(token);

    if (error || !data.user) {
      throw new UnauthorizedException({
        error: {
          code: 'UNAUTHORIZED',
          message: 'Sessão inválida ou expirada',
          details: {},
        },
      });
    }

    return {
      user: {
        id: data.user.id,
        email: data.user.email,
      },
    };
  }

  async logout() {
    const supabase = this.supabaseService.getClient();

    const { error } = await supabase.auth.signOut();

    if (error) {
      throw new BadRequestException({
        error: {
          code: 'LOGOUT_FAILED',
          message: error.message,
          details: {},
        },
      });
    }

    return {
      ok: true,
    };
  }

  async requestPasswordReset(dto: PasswordResetRequestDto) {
    const supabase = this.supabaseService.getClient();

    const { error } = await supabase.auth.resetPasswordForEmail(
      dto.email,
    );

    if (error) {
      throw new BadRequestException({
        error: {
          code: 'PASSWORD_RESET_FAILED',
          message: error.message,
          details: {},
        },
      });
    }

    return {
      ok: true,
    };
  }

  async confirmPasswordReset(
    dto: PasswordResetConfirmDto,
    authorization?: string,
  ) {
    if (
      typeof authorization !== 'string' ||
      !authorization.startsWith('Bearer ')
    ) {
      throw new UnauthorizedException({
        error: {
          code: 'UNAUTHORIZED',
          message: 'Sessão de recuperação inválida ou expirada',
          details: {},
        },
      });
    }

    const accessToken = authorization.substring(7);

    const supabase = this.supabaseService.getClient();

    const { data: userData, error: userError } =
      await supabase.auth.getUser(accessToken);

    if (userError || !userData.user) {
      throw new UnauthorizedException({
        error: {
          code: 'TOKEN_INVALID',
          message: 'Token inválido ou expirado',
          details: {},
        },
      });
    }

    // Atualiza a senha
    const { error } = await supabase.auth.updateUser(
      {
        password: dto.newPassword,
      },
      {
        // dependendo de como seu client está configurado,
        // pode ser necessário trabalhar com a sessão/token
      },
    );

    if (error) {
      throw new BadRequestException({
        error: {
          code: 'PASSWORD_UPDATE_FAILED',
          message: error.message,
          details: {},
        },
      });
    }

    return {
      ok: true,
    };
  }
}
