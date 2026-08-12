import {
  BadRequestException,
  ConflictException,
  Injectable,
  UnauthorizedException,
  UnprocessableEntityException,
} from '@nestjs/common';
import { Request, Response } from 'express';

import { LoginEmailDto } from './dto/login-email.dto';
import { SignupEmailDto } from './dto/signup-email.dto';
import { SupabaseService } from '../supabase/supabase.service';

@Injectable()
export class AuthService {
  constructor(private readonly supabaseService: SupabaseService) {}

  private setSessionCookies(res: Response | undefined, session: { access_token?: string; refresh_token?: string } | null | undefined) {
    if (!res || !session) {
      return;
    }

    if (session.access_token) {
      res.cookie('access', session.access_token, {
        httpOnly: true,
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production',
        path: '/',
      });
    }

    if (session.refresh_token) {
      res.cookie('refresh', session.refresh_token, {
        httpOnly: true,
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production',
        path: '/',
      });
    }
  }

  async signup(dto: SignupEmailDto, res?: Response) {
    const supabase = this.supabaseService.getClient();
    const { data, error } = await supabase.auth.signUp({
      email: dto.email,
      password: dto.password,
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

    this.setSessionCookies(res, data.session);

    return {
      user: {
        id: data.user?.id ?? '',
        email: data.user?.email ?? dto.email,
      },
      requiresEmailVerification: !data.session,
    };
  }

  async login(dto: LoginEmailDto, res?: Response) {
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

    this.setSessionCookies(res, data.session);

    return {
      user: {
        id: data.user?.id ?? '',
        email: data.user?.email ?? dto.email,
        mfaEnabled: false,
      },
    };
  }

  async getCurrentUser(req: Request) {
    const authHeader = req.headers.authorization;
    const accessToken = req.cookies?.access ?? (typeof authHeader === 'string' ? authHeader.replace('Bearer ', '') : '');

    if (!accessToken) {
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
        id: req.user?.id ?? 'current-user',
        email: req.user?.email ?? 'user@email.com',
        role: req.user?.role ?? 'owner',
        mfaEnabled: Boolean(req.user?.mfaEnabled),
      },
    };
  }

  async logout(_req: Request, res: Response) {
    res.clearCookie('access');
    res.clearCookie('refresh');
    return null;
  }

  async requestPasswordReset(dto: { email: string }) {
    return {
      ok: true,
    };
  }

  async confirmPasswordReset(dto: { token: string; newPassword: string }) {
    if (!dto.token) {
      throw new BadRequestException({
        error: {
          code: 'TOKEN_INVALID',
          message: 'Token inválido',
          details: {},
        },
      });
    }

    return {
      ok: true,
    };
  }
}
