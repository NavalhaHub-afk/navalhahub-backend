import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';

import { SupabaseService } from '../supabase/supabase.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly supabaseService: SupabaseService,
  ) {}

  async signupWithEmail(
  email: string,
  password: string,
  fullName: string,
  phone?: string,
) {
  console.info('signupWithEmail', {
    email,
    phone,
    fullName,
  });

  const supabase = this.supabaseService.getClient();

  const { data, error } = await supabase.auth.signUp({
    email,
    password,
    phone,
    options: {
      data: {
        full_name: fullName,
      },
    },
  });

  console.info('signupWithEmail', {
    user: data.user,
    session: data.session,
    error,
  });

  if (error) {
    throw new BadRequestException(error.message);
  }

  return {
    user: data.user,
    session: data.session,
  };
}

  async loginWithEmail(
    email: string,
    password: string,
  ) {
    const supabase = this.supabaseService.getClient();

    const { data, error } =
      await supabase.auth.signInWithPassword({
        email,
        password,
      });

    if (error) {
      throw new UnauthorizedException(
        'Email ou senha inválidos',
      );
    }

    return {
      user: data.user,
      session: data.session,
    };
  }

  async requestEmailOtp(email: string) {
    const supabase = this.supabaseService.getClient();

    const { error } = await supabase.auth.signInWithOtp({
      email,
    });

    if (error) {
      throw new BadRequestException(error.message);
    }

    return {
      message: 'OTP enviado para o email',
    };
  }

  async requestPhoneOtp(phone: string) {
    const supabase = this.supabaseService.getClient();

    const { error } = await supabase.auth.signInWithOtp({
      phone,
    });

    if (error) {
      throw new BadRequestException(error.message);
    }

    return {
      message: 'OTP enviado para o telefone',
    };
  }

  async verifyEmailOtp(
    email: string,
    token: string,
  ) {
    const supabase = this.supabaseService.getClient();

    const { data, error } =
      await supabase.auth.verifyOtp({
        email,
        token,
        type: 'email',
      });

    if (error) {
      throw new UnauthorizedException(
        'OTP inválido ou expirado',
      );
    }

    return {
      user: data.user,
      session: data.session,
    };
  }

  async verifyPhoneOtp(
    phone: string,
    token: string,
  ) {
    const supabase = this.supabaseService.getClient();

    const { data, error } =
      await supabase.auth.verifyOtp({
        phone,
        token,
        type: 'sms',
      });

    if (error) {
      throw new UnauthorizedException(
        'OTP inválido ou expirado',
      );
    }

    return {
      user: data.user,
      session: data.session,
    };
  }
}
