

export class VerifyOtpDto{
    type!: 'email' | 'phone';
    email?: string;
    phone?: string;
    token!: string;
}