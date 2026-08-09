
CREATE EXTENSION IF NOT EXISTS btree_gist WITH SCHEMA public;

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;


CREATE SCHEMA IF NOT EXISTS "public";


ALTER SCHEMA "public" OWNER TO "pg_database_owner";


COMMENT ON SCHEMA "public" IS 'standard public schema';



CREATE TYPE "public"."app_role" AS ENUM (
    'owner',
    'barber',
    'customer'
);


ALTER TYPE "public"."app_role" OWNER TO "postgres";


CREATE TYPE "public"."audit_level" AS ENUM (
    'info',
    'warning',
    'critical'
);


ALTER TYPE "public"."audit_level" OWNER TO "postgres";


CREATE TYPE "public"."checkout_item" AS (
	"product_id" "uuid",
	"quantity" integer,
	"unit_price" numeric(10,2),
	"total_price" numeric(10,2)
);


ALTER TYPE "public"."checkout_item" OWNER TO "postgres";


CREATE TYPE "public"."commission_rule_type" AS ENUM (
    'global',
    'barber_specific',
    'service_specific'
);


ALTER TYPE "public"."commission_rule_type" OWNER TO "postgres";


CREATE TYPE "public"."expense_recurrence" AS ENUM (
    'one_off',
    'weekly',
    'monthly',
    'yearly'
);


ALTER TYPE "public"."expense_recurrence" OWNER TO "postgres";


CREATE DOMAIN "public"."ip_address" AS "text"
	CONSTRAINT "ip_address_check" CHECK (((VALUE ~ '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,3})?$'::"text") OR (VALUE ~ '^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(/[0-9]{1,3})?$'::"text") OR (VALUE IS NULL)));


ALTER DOMAIN "public"."ip_address" OWNER TO "postgres";


CREATE TYPE "public"."transaction_status" AS ENUM (
    'pending',
    'completed',
    'cancelled'
);


ALTER TYPE "public"."transaction_status" OWNER TO "postgres";


CREATE TYPE "public"."transaction_type" AS ENUM (
    'income',
    'expense',
    'commission_credit',
    'commission_payout'
);


ALTER TYPE "public"."transaction_type" OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."add_allowed_anon_action"("p_action" "text", "p_description" "text") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
    -- Only service_role can add actions
    IF auth.role() != 'service_role' THEN
        RAISE EXCEPTION 'Only service_role can manage allowed actions';
    END IF;

    INSERT INTO public.allowed_anon_actions (action, description)
    VALUES (p_action, p_description)
    ON CONFLICT (action) DO UPDATE
        SET description = EXCLUDED.description,
            enabled = true;
END;
$$;


ALTER FUNCTION "public"."add_allowed_anon_action"("p_action" "text", "p_description" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."analyze_threat_events"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
  v_fail_count INT;
  v_attacker_ip INET;
BEGIN
  IF NEW.event_type = 'auth.otp_send_failed' OR NEW.event_type = 'auth.brute_force_attempt' THEN
    v_attacker_ip := (NEW.details->>'ip')::INET;
    IF v_attacker_ip IS NOT NULL THEN
      SELECT count(*) INTO v_fail_count FROM public.sovereign_audit_events
      WHERE (details->>'ip')::INET = v_attacker_ip AND created_at > NOW() - INTERVAL '1 hour';
      IF v_fail_count >= 5 THEN
        INSERT INTO public.blacklisted_ips (ip_address, reason, expires_at)
        VALUES (v_attacker_ip, 'Automated Bot Detected', NOW() + INTERVAL '2 hours')
        ON CONFLICT (ip_address) DO UPDATE SET expires_at = NOW() + INTERVAL '2 hours', banned_at = NOW();
      END IF;
    END IF;
  END IF;
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."analyze_threat_events"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."anonymize_inactive_customers"() RETURNS integer
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'pg_catalog', 'public', 'pg_temp'
    AS $$
DECLARE
  v_affected INTEGER;
BEGIN
  UPDATE public.customers
  SET
    name     = 'ANONIMIZADO',
    email    = CONCAT('anon_', id::text, '@anonimizado.invalid'),
    phone    = '00000000000',
    updated_at = NOW()
  WHERE id IN (
    SELECT c.id FROM public.customers c
    LEFT JOIN public.appointments a ON c.id = a.customer_id
    GROUP BY c.id
    HAVING
      MAX(a.appointment_date) < NOW() - INTERVAL '5 years'
      OR (MAX(a.appointment_date) IS NULL AND c.created_at < NOW() - INTERVAL '5 years')
  )
  AND name != 'ANONIMIZADO'; -- Idempotência

  GET DIAGNOSTICS v_affected = ROW_COUNT;
  RETURN v_affected;
END;
$$;


ALTER FUNCTION "public"."anonymize_inactive_customers"() OWNER TO "postgres";


COMMENT ON FUNCTION "public"."anonymize_inactive_customers"() IS 'Anonimiza clientes inativos há 5 anos (LGPD Art. 15)';



CREATE OR REPLACE FUNCTION "public"."apply_data_retention_policy"() RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'pg_catalog', 'public', 'pg_temp'
    AS $$
DECLARE
  v_customers    INTEGER;
  v_appointments INTEGER;
  v_logs         INTEGER;
BEGIN
  v_customers    := public.anonymize_inactive_customers();
  v_appointments := public.delete_old_appointments();
  v_logs         := public.cleanup_audit_logs();

  -- Registrar para auditoria interna
  INSERT INTO public.data_retention_log (operation, records_affected)
  VALUES
    ('anonymize_customers', v_customers),
    ('delete_appointments', v_appointments),
    ('cleanup_logs',        v_logs);

  RAISE NOTICE '[LGPD] Retenção aplicada: % clientes, % agendamentos, % logs',
    v_customers, v_appointments, v_logs;

  RETURN jsonb_build_object(
    'customers_anonymized',  v_customers,
    'appointments_deleted',  v_appointments,
    'logs_cleaned',          v_logs,
    'executed_at',           NOW()
  );
END;
$$;


ALTER FUNCTION "public"."apply_data_retention_policy"() OWNER TO "postgres";


COMMENT ON FUNCTION "public"."apply_data_retention_policy"() IS 'âœ… ATIVA: Agendada para rodar diariamente via pg_cron Ã s 06:30 UTC.';



CREATE OR REPLACE FUNCTION "public"."audit_barbers_commission_changes"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
BEGIN
  IF (OLD.commission_percentage IS DISTINCT FROM NEW.commission_percentage) THEN
    PERFORM log_audit_event(
        'barbers', 
        NEW.id, 
        'UPDATE_COMMISSION', 
        'financial', 
        jsonb_build_object('rate', OLD.commission_percentage), 
        jsonb_build_object('rate', NEW.commission_percentage)
    );
  END IF;
  RETURN NULL;
END;
$$;


ALTER FUNCTION "public"."audit_barbers_commission_changes"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."audit_barbershop_status_changes"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
BEGIN
  IF (OLD.subscription_status IS DISTINCT FROM NEW.subscription_status) THEN
    PERFORM log_audit_event(
        'barbershops', 
        NEW.id, 
        'UPDATE_SUBSCRIPTION_STATUS', 
        'business', 
        jsonb_build_object('status', OLD.subscription_status), 
        jsonb_build_object('status', NEW.subscription_status)
    );
  END IF;
  RETURN NULL;
END;
$$;


ALTER FUNCTION "public"."audit_barbershop_status_changes"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."audit_commissions_trigger"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
BEGIN
  PERFORM public.log_audit_event(
    'commissions',
    COALESCE(NEW.id, OLD.id),
    TG_OP,                   -- ACTION (INSERT, UPDATE, DELETE)
    'financial',             -- CATEGORY
    CASE WHEN TG_OP IN ('DELETE','UPDATE') THEN to_jsonb(OLD) ELSE NULL END,
    CASE WHEN TG_OP IN ('INSERT','UPDATE') THEN to_jsonb(NEW) ELSE NULL END
  );
  RETURN NULL;
END;
$$;


ALTER FUNCTION "public"."audit_commissions_trigger"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."audit_services_financial_changes"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
BEGIN
  -- Detect Price or Commission Change
  IF (OLD.price IS DISTINCT FROM NEW.price) OR (OLD.commission_percentage IS DISTINCT FROM NEW.commission_percentage) THEN
    PERFORM log_audit_event(
        'services', 
        NEW.id, 
        'UPDATE_FINANCIAL', 
        'financial', 
        jsonb_build_object('price', OLD.price, 'commission', OLD.commission_percentage), 
        jsonb_build_object('price', NEW.price, 'commission', NEW.commission_percentage)
    );
  END IF;
  RETURN NULL;
END;
$$;


ALTER FUNCTION "public"."audit_services_financial_changes"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."audit_user_roles_changes"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
BEGIN
  IF (TG_OP = 'UPDATE' AND OLD.role IS DISTINCT FROM NEW.role) THEN
    PERFORM log_audit_event('user_roles', NEW.user_id, 'UPDATE_ROLE', 'security', to_jsonb(OLD), to_jsonb(NEW));
  ELSIF (TG_OP = 'INSERT') THEN
    PERFORM log_audit_event('user_roles', NEW.user_id, 'GRANT_ROLE', 'security', NULL, to_jsonb(NEW));
  ELSIF (TG_OP = 'DELETE') THEN
    PERFORM log_audit_event('user_roles', OLD.user_id, 'REVOKE_ROLE', 'security', to_jsonb(OLD), NULL);
  END IF;
  RETURN NULL;
END;
$$;


ALTER FUNCTION "public"."audit_user_roles_changes"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."auto_track_appointment_events"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_owner_id UUID;
  v_existing_appointments INTEGER;
  v_existing_completed INTEGER;
BEGIN
  SELECT owner_id INTO v_owner_id
  FROM public.barbershops
  WHERE id = NEW.barbershop_id;
  
  IF v_owner_id IS NULL THEN
    RETURN NEW;
  END IF;
  
  -- INSERT: verificar se é primeiro agendamento
  IF TG_OP = 'INSERT' THEN
    SELECT COUNT(*) INTO v_existing_appointments
    FROM public.appointments
    WHERE barbershop_id = NEW.barbershop_id
    AND id != NEW.id;
    
    IF v_existing_appointments = 0 THEN
      PERFORM public.track_user_event(
        v_owner_id,
        'first_appointment_created',
        NEW.barbershop_id,
        jsonb_build_object('appointment_id', NEW.id)
      );
    END IF;
  END IF;
  
  -- UPDATE: verificar se é primeiro completado
  IF TG_OP = 'UPDATE' AND NEW.status = 'completed' AND OLD.status != 'completed' THEN
    SELECT COUNT(*) INTO v_existing_completed
    FROM public.appointments
    WHERE barbershop_id = NEW.barbershop_id
    AND status = 'completed'
    AND id != NEW.id;
    
    IF v_existing_completed = 0 THEN
      PERFORM public.track_user_event(
        v_owner_id,
        'first_appointment_completed',
        NEW.barbershop_id,
        jsonb_build_object('appointment_id', NEW.id, 'aha_moment', true)
      );
    END IF;
  END IF;
  
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."auto_track_appointment_events"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."auto_track_barber_added"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_owner_id UUID;
  v_existing_count INTEGER;
BEGIN
  -- Buscar owner da barbearia
  SELECT owner_id INTO v_owner_id
  FROM public.barbershops
  WHERE id = NEW.barbershop_id;
  
  -- Verificar se é o primeiro barbeiro
  SELECT COUNT(*) INTO v_existing_count
  FROM public.barbers
  WHERE barbershop_id = NEW.barbershop_id
  AND id != NEW.id;
  
  IF v_existing_count = 0 AND v_owner_id IS NOT NULL THEN
    PERFORM public.track_user_event(
      v_owner_id,
      'first_barber_added',
      NEW.barbershop_id,
      jsonb_build_object('barber_id', NEW.id, 'barber_name', NEW.name)
    );
  END IF;
  
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."auto_track_barber_added"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."auto_track_service_added"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_owner_id UUID;
  v_existing_count INTEGER;
BEGIN
  SELECT owner_id INTO v_owner_id
  FROM public.barbershops
  WHERE id = NEW.barbershop_id;
  
  SELECT COUNT(*) INTO v_existing_count
  FROM public.services
  WHERE barbershop_id = NEW.barbershop_id
  AND id != NEW.id;
  
  IF v_existing_count = 0 AND v_owner_id IS NOT NULL THEN
    PERFORM public.track_user_event(
      v_owner_id,
      'first_service_added',
      NEW.barbershop_id,
      jsonb_build_object('service_id', NEW.id, 'service_name', NEW.name)
    );
  END IF;
  
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."auto_track_service_added"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."buffer_bi_event"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
    -- 3.1. Handle INSERT or Status Change to Confirmed
    IF (TG_OP = 'INSERT' AND NEW.status = 'confirmed') OR (TG_OP = 'UPDATE' AND OLD.status != 'confirmed' AND NEW.status = 'confirmed') THEN
         INSERT INTO public.bi_log (tenant_id, metric_date, metric_type, metric_value)
         VALUES (NEW.barbershop_id, NEW.appointment_date, 'appointment_count', 1);

         IF NEW.price > 0 THEN
             INSERT INTO public.bi_log (tenant_id, metric_date, metric_type, metric_value)
             VALUES (NEW.barbershop_id, NEW.appointment_date, 'revenue', NEW.price);
         END IF;
    END IF;

    -- 3.2. Handle Cancellation (Negative Log)
    IF (TG_OP = 'UPDATE' AND OLD.status = 'confirmed' AND NEW.status = 'cancelled') THEN
         INSERT INTO public.bi_log (tenant_id, metric_date, metric_type, metric_value)
         VALUES (NEW.barbershop_id, NEW.appointment_date, 'appointment_count', -1);

         IF NEW.price > 0 THEN
             INSERT INTO public.bi_log (tenant_id, metric_date, metric_type, metric_value)
             VALUES (NEW.barbershop_id, NEW.appointment_date, 'revenue', -1 * NEW.price);
         END IF;
    END IF;

    -- 3.3. Handle Date/Price Changes for Confirmed Appointments (V8 FIX)
    IF (TG_OP = 'UPDATE' AND OLD.status = 'confirmed' AND NEW.status = 'confirmed') THEN
        IF OLD.appointment_date IS DISTINCT FROM NEW.appointment_date THEN
             INSERT INTO public.bi_log (tenant_id, metric_date, metric_type, metric_value)
             VALUES (OLD.barbershop_id, OLD.appointment_date, 'appointment_count', -1);
             IF OLD.price > 0 THEN
                 INSERT INTO public.bi_log (tenant_id, metric_date, metric_type, metric_value)
                 VALUES (OLD.barbershop_id, OLD.appointment_date, 'revenue', -1 * OLD.price);
             END IF;

             INSERT INTO public.bi_log (tenant_id, metric_date, metric_type, metric_value)
             VALUES (NEW.barbershop_id, NEW.appointment_date, 'appointment_count', 1);
             IF NEW.price > 0 THEN
                 INSERT INTO public.bi_log (tenant_id, metric_date, metric_type, metric_value)
                 VALUES (NEW.barbershop_id, NEW.appointment_date, 'revenue', NEW.price);
             END IF;
        
        ELSIF OLD.price IS DISTINCT FROM NEW.price THEN
             INSERT INTO public.bi_log (tenant_id, metric_date, metric_type, metric_value)
             VALUES (NEW.barbershop_id, NEW.appointment_date, 'revenue', NEW.price - OLD.price);
        END IF;
    END IF;

    RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."buffer_bi_event"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."calculate_appointment_end_time"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_duration_minutes INTEGER;
BEGIN
  -- 1. Buscar duração do serviço explicitamente
  SELECT duration_minutes INTO v_duration_minutes
  FROM services
  WHERE id = NEW.service_id;

  -- 2. HARDENING: Se o serviço não existe, ABORTAR IMEDIATAMENTE.
  -- Não assumimos nada. Protegemos a integridade da agenda.
  IF v_duration_minutes IS NULL THEN
     RAISE EXCEPTION 'Critical Integrity Violation: Service ID % not found or invalid. Cannot calculate appointment duration.', NEW.service_id
     USING HINT = 'Ensure the Service ID exists and has a valid duration_minutes.';
  END IF;

  -- 3. Calcular appointment_end_time com dado confirmado
  NEW.appointment_end_time := NEW.appointment_time + (v_duration_minutes || ' minutes')::interval;
  
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."calculate_appointment_end_time"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."calculate_commission_for_appointment"("appt_id" "uuid") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
    v_barbershop_id UUID;
    v_barber_id UUID;
    v_service_id UUID;
    v_price NUMERIC;
    v_status TEXT;
    v_appointment_date DATE;
    v_rule RECORD;
    v_commission_amount NUMERIC := 0;
    v_rule_applied TEXT;
BEGIN
    -- 1. Get Appointment Details
    SELECT 
        barbershop_id, 
        barber_id, 
        service_id, 
        price, 
        status,
        appointment_date
    INTO 
        v_barbershop_id, 
        v_barber_id, 
        v_service_id, 
        v_price, 
        v_status,
        v_appointment_date
    FROM appointments
    WHERE id = appt_id;

    -- Validation: Only calculate for completed appointments
    IF v_status IS DISTINCT FROM 'completed' THEN
        RETURN;
    END IF;

    -- TRUE ZERO TRUST: Fallback para o preço do serviço caso seja agendamento legado
    IF v_price IS NULL THEN
        SELECT s.price INTO v_price 
        FROM public.services s 
        WHERE s.id = v_service_id;
    END IF;
    
    v_price := COALESCE(v_price, 0);

    -- 🛡️ AI GUARDS: STRICT IDEMPOTENCY CHECK (V-20 FIX)
    -- We MUST check for the 'income' transaction, not the 'commission_credit'.
    -- If commission was 0%, the previous flawed logic would allow double-booking the income.
    IF EXISTS (
        SELECT 1 FROM financial_ledger 
        WHERE appointment_id = appt_id 
        AND transaction_type = 'income'
    ) THEN
        RETURN; -- 🔒 Atomic stop: Revenue was already computed for this appointment.
    END IF;

    -- 2. Find the applicable Commission Rule (Hierarchy)
    SELECT * INTO v_rule FROM commission_settings
    WHERE barbershop_id = v_barbershop_id
      AND rule_type = 'service_specific'
      AND service_id = v_service_id
      AND (barber_id = v_barber_id OR barber_id IS NULL)
    ORDER BY barber_id NULLS LAST 
    LIMIT 1;

    IF v_rule IS NULL THEN
        SELECT * INTO v_rule FROM commission_settings
        WHERE barbershop_id = v_barbershop_id
          AND rule_type = 'barber_specific'
          AND barber_id = v_barber_id
        LIMIT 1;
    END IF;

    IF v_rule IS NULL THEN
        SELECT * INTO v_rule FROM commission_settings
        WHERE barbershop_id = v_barbershop_id
          AND rule_type = 'global'
        LIMIT 1;
    END IF;

    -- 3. Calculate Amount
    IF v_rule IS NOT NULL THEN
        IF v_rule.fixed_amount IS NOT NULL AND v_rule.fixed_amount > 0 THEN
            v_commission_amount := v_rule.fixed_amount;
            v_rule_applied := 'Fixed: ' || v_rule.fixed_amount;
        ELSIF v_rule.percentage IS NOT NULL AND v_rule.percentage > 0 THEN
            v_commission_amount := v_price * (v_rule.percentage / 100);
            v_rule_applied := 'Percentage: ' || v_rule.percentage || '%';
        END IF;
    ELSE
        v_commission_amount := 0;
        v_rule_applied := 'No Rule Found';
    END IF;

    -- 4. Insert into Ledger
    
    -- A. Log Commission Liability
    IF v_commission_amount > 0 THEN
        INSERT INTO financial_ledger (
            barbershop_id,
            appointment_id,
            appointment_date,
            barber_id,
            transaction_type,
            amount,
            description,
            status
        ) VALUES (
            v_barbershop_id,
            appt_id,
            v_appointment_date,
            v_barber_id,
            'commission_credit',
            v_commission_amount,
            'Comissão Referente ao Agendamento #' || substring(appt_id::text, 1, 8) || ' (' || v_rule_applied || ')',
            'pending'
        );
    END IF;

    -- B. Log Income (Revenue)
    INSERT INTO financial_ledger (
        barbershop_id,
        appointment_id,
        appointment_date,
        barber_id,
        transaction_type,
        amount,
        description,
        status
    ) VALUES (
        v_barbershop_id,
        appt_id,
        v_appointment_date,
        v_barber_id,
        'income',
        v_price,
        'Receita de Serviço #' || substring(appt_id::text, 1, 8),
        'completed'
    );

END;
$$;


ALTER FUNCTION "public"."calculate_commission_for_appointment"("appt_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."cancel_appointment"("p_appointment_id" "uuid", "p_reason" "text" DEFAULT NULL::"text") RETURNS boolean
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'extensions'
    AS $$
DECLARE
  v_appointment appointments%ROWTYPE;
  v_current_user UUID;
  v_is_customer  BOOLEAN;
  v_is_owner     BOOLEAN;
BEGIN
  v_current_user := auth.uid();

  IF v_current_user IS NULL THEN
    RAISE EXCEPTION 'ERR_UNAUTHORIZED: Autenticação necessária';
  END IF;

  -- Fetch the appointment (not already cancelled)
  SELECT * INTO v_appointment
  FROM public.appointments
  WHERE id = p_appointment_id
    AND status != 'cancelled';

  IF NOT FOUND THEN
    RAISE EXCEPTION 'ERR_NOT_FOUND: Agendamento não encontrado ou já cancelado';
  END IF;

  -- Authorization check:
  -- 1. The customer who owns the appointment
  -- 2. The barbershop owner
  SELECT EXISTS (
    SELECT 1 FROM public.customers
    WHERE id = v_appointment.customer_id
      AND user_id = v_current_user
  ) INTO v_is_customer;

  SELECT EXISTS (
    SELECT 1 FROM public.barbershops
    WHERE id = v_appointment.barbershop_id
      AND owner_id = v_current_user
  ) INTO v_is_owner;

  IF NOT (v_is_customer OR v_is_owner) THEN
    RAISE EXCEPTION 'ERR_UNAUTHORIZED: Sem permissão para cancelar este agendamento';
  END IF;

  -- Cancel the appointment
  UPDATE public.appointments
  SET status              = 'cancelled',
      cancelled_at        = NOW(),
      cancellation_reason = p_reason,
      updated_at          = NOW()
  WHERE id = p_appointment_id;

  -- Audit log (SECURITY DEFINER allows this even after REVOKE above)
  INSERT INTO public.audit_logs (action, user_id, metadata, level)
  VALUES (
    'appointment.cancelled',
    v_current_user,
    jsonb_build_object(
      'appointment_id', p_appointment_id,
      'reason', p_reason,
      'cancelled_by_owner', v_is_owner
    ),
    'info'
  );

  RETURN TRUE;
END;
$$;


ALTER FUNCTION "public"."cancel_appointment"("p_appointment_id" "uuid", "p_reason" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."cancel_appointment_atomically"("p_appointment_id" "uuid", "p_token" "text" DEFAULT NULL::"text", "p_reason" "text" DEFAULT NULL::"text") RETURNS json
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_appointment record;
  v_barbershop record;
  v_customer record;
  v_service_name text;
  v_barber_name text;
  v_user_id uuid;
  v_actor text := 'customer'; -- Default
  v_cancelled_by_user_id uuid;
  v_token_record record;
  v_hours_diff numeric;
  v_cancellation_window integer := 2; -- Default 2 hours
  v_queue_payload jsonb;
  v_audit_id uuid;
BEGIN
  -- 1. GET CURRENT USER
  v_user_id := auth.uid();

  -- 2. FETCH APPOINTMENT DETAILS
  SELECT 
    a.*,
    b.owner_id,
    b.phone as barbershop_phone,
    b.name as barbershop_name,
    c.name as customer_name,
    c.phone as customer_phone,
    c.user_id as customer_user_id,
    s.name as service_name,
    bar.name as barber_name,
    bar.user_id as barber_user_id
  INTO v_appointment
  FROM public.appointments a
  JOIN public.barbershops b ON a.barbershop_id = b.id
  JOIN public.customers c ON a.customer_id = c.id
  JOIN public.services s ON a.service_id = s.id
  JOIN public.barbers bar ON a.barber_id = bar.id
  WHERE a.id = p_appointment_id;

  IF v_appointment IS NULL THEN
    RAISE EXCEPTION 'APPOINTMENT_NOT_FOUND: Agendamento não encontrado';
  END IF;

  IF v_appointment.status = 'cancelled' THEN
     RAISE EXCEPTION 'APPOINTMENT_ALREADY_CANCELLED: Este agendamento já foi cancelado';
  END IF;

  -- 3. AUTHENTICATION & PERMISSION CHECK
  IF v_user_id IS NOT NULL THEN
     v_cancelled_by_user_id := v_user_id;
     
     IF v_appointment.owner_id = v_user_id THEN
        v_actor := 'owner';
     ELSIF v_appointment.barber_user_id = v_user_id THEN
        v_actor := 'barber';
     ELSIF v_appointment.customer_user_id = v_user_id THEN
        v_actor := 'customer';
     ELSE
        -- Logged in, but not related? Check Token as fallback
        IF p_token IS NULL THEN
           RAISE EXCEPTION 'UNAUTHORIZED: Você não tem permissão para cancelar este agendamento';
        END IF;
     END IF;
  END IF;

  -- 4. TOKEN VALIDATION (If no Auth or Explicit Token Usage)
  IF v_user_id IS NULL OR p_token IS NOT NULL THEN
     IF p_token IS NOT NULL THEN
        SELECT * INTO v_token_record 
        FROM public.appointment_tokens 
        WHERE token = p_token AND appointment_id = p_appointment_id;

        IF v_token_record IS NULL THEN
           RAISE EXCEPTION 'TOKEN_INVALID: Link inválido';
        END IF;

        IF v_token_record.used_at IS NOT NULL THEN
           RAISE EXCEPTION 'TOKEN_ALREADY_USED: Este link já foi utilizado';
        END IF;
        
        IF v_token_record.expires_at < NOW() THEN
           RAISE EXCEPTION 'TOKEN_EXPIRED: Link expirado';
        END IF;
        
        -- Token validated, actor is customer (unless overridden by Auth above)
        IF v_user_id IS NULL THEN
            v_actor := 'customer';
        END IF;
     ELSE
        -- No User, No Token
        RAISE EXCEPTION 'AUTH_OR_TOKEN_REQUIRED: Autenticação necessária';
     END IF;
  END IF;

  -- 5. TIME WINDOW CHECK
  -- Calculate hours difference
  v_hours_diff := EXTRACT(EPOCH FROM (
    (v_appointment.appointment_date + v_appointment.appointment_time) - NOW()
  )) / 3600;

  -- TODO: Read from settings in future. For now, 2h.
  IF v_hours_diff < v_cancellation_window AND v_actor = 'customer' THEN
     RAISE EXCEPTION 'CANCELLATION_TOO_LATE: Cancelamento permitido apenas com % horas de antecedência', v_cancellation_window;
  END IF;

  -- 6. EXECUTE CANCELLATION (Atomic Update)
  UPDATE public.appointments
  SET 
    status = 'cancelled',
    updated_at = NOW()
  WHERE id = p_appointment_id;

  -- 7. MARK TOKEN USED (If applicable)
  IF p_token IS NOT NULL THEN
     UPDATE public.appointment_tokens
     SET used_at = NOW()
     WHERE token = p_token;
  END IF;

  -- 8. AUDIT LOG
  INSERT INTO public.appointment_cancellations (
    appointment_id,
    cancelled_by,
    cancelled_by_user_id,
    cancellation_reason,
    hours_before_appointment,
    whatsapp_sent
  ) VALUES (
    p_appointment_id,
    v_actor,
    v_cancelled_by_user_id,
    p_reason,
    ROUND(v_hours_diff::numeric, 2),
    false -- Will be updated by worker or just tracked in queue
  ) RETURNING id INTO v_audit_id;

  -- 9. ASYNC NOTIFICATION (Queue)
  v_queue_payload := jsonb_build_object(
      'appointmentId', p_appointment_id,
      'type', CASE WHEN v_actor = 'customer' THEN 'cancellation_by_customer' ELSE 'cancellation_by_barber' END,
      'reason', p_reason,
      'customerName', v_appointment.customer_name,
      'barbershopName', v_appointment.barbershop_name,
      'appointmentDate', v_appointment.appointment_date,
      'appointmentTime', v_appointment.appointment_time,
      'serviceName', v_appointment.service_name,
      'phoneToNotify', CASE WHEN v_actor = 'customer' THEN v_appointment.barbershop_phone ELSE v_appointment.customer_phone END
  );

  INSERT INTO public.notification_queue (
      appointment_id,
      type,
      payload,
      status
  ) VALUES (
      p_appointment_id,
      'cancellation',
      v_queue_payload,
      'pending'
  );

  RETURN json_build_object(
    'success', true,
    'message', 'Agendamento cancelado com sucesso'
  );

END;
$$;


ALTER FUNCTION "public"."cancel_appointment_atomically"("p_appointment_id" "uuid", "p_token" "text", "p_reason" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."check_account_lockout"("p_email" "text") RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'pg_catalog', 'public', 'pg_temp'
    AS $$
DECLARE
  v_is_locked BOOLEAN;
  v_unlock_time TIMESTAMPTZ;
BEGIN
  -- Input validation: reject empty/null email
  IF p_email IS NULL OR trim(p_email) = '' THEN
    RETURN jsonb_build_object('locked', false, 'reason', 'invalid_input');
  END IF;

  v_is_locked := public.is_account_locked_internal(p_email);

  IF v_is_locked THEN
    -- Calculate approximate unlock time based on most recent attempt
    SELECT MAX(attempted_at) + INTERVAL '15 minutes'
    INTO v_unlock_time
    FROM public.login_attempts
    WHERE email = lower(p_email)
      AND success = false;

    RETURN jsonb_build_object(
      'locked', true,
      'unlock_at', v_unlock_time,
      'message', 'Conta temporariamente bloqueada por excesso de tentativas.'
    );
  END IF;

  RETURN jsonb_build_object('locked', false);
END;
$$;


ALTER FUNCTION "public"."check_account_lockout"("p_email" "text") OWNER TO "postgres";


COMMENT ON FUNCTION "public"."check_account_lockout"("p_email" "text") IS '[SOVEREIGN V4.9] Public-safe lockout status check. Returns boolean only, no data leakage.
Same response for locked accounts and non-existent accounts prevents email enumeration.
Replaces the client-side is_account_locked() function. Fixes V-20.';



CREATE OR REPLACE FUNCTION "public"."check_aha_moment"("p_user_id" "uuid") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.user_events
    WHERE user_id = p_user_id
    AND event_type = 'first_appointment_completed'
  );
$$;


ALTER FUNCTION "public"."check_aha_moment"("p_user_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."check_and_expire_trials"() RETURNS TABLE("barbershop_id" "uuid", "barbershop_name" "text", "expired" boolean)
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
BEGIN
  -- Update expired trials
  -- Business Rule: trial_ends_at < NOW() AND status = 'trial'
  UPDATE barbershops
  SET 
    subscription_status = 'expired',
    subscription_plan = 'free',
    updated_at = NOW()
  WHERE subscription_status = 'trial'
    AND trial_ends_at IS NOT NULL
    AND trial_ends_at < NOW();
  
  -- Return trials that were just expired
  -- Only return those updated in the last minute (recently expired)
  RETURN QUERY
  SELECT 
    b.id,
    b.name,
    TRUE as expired
  FROM barbershops b
  WHERE b.subscription_status = 'expired'
    AND b.trial_ends_at IS NOT NULL
    AND b.trial_ends_at < NOW()
    AND b.updated_at > NOW() - INTERVAL '1 minute'; -- Recently expired
END;
$$;


ALTER FUNCTION "public"."check_and_expire_trials"() OWNER TO "postgres";


COMMENT ON FUNCTION "public"."check_and_expire_trials"() IS 'Verifica e expira trials que passaram da data de término. Deve ser chamada periodicamente por cron job.';



CREATE OR REPLACE FUNCTION "public"."check_appointment_conflict"("p_barber_id" "uuid", "p_appointment_date" "date", "p_appointment_time" time without time zone, "p_duration_minutes" integer, "p_padding_minutes" integer DEFAULT 0, "p_exclude_appointment_id" "uuid" DEFAULT NULL::"uuid") RETURNS boolean
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_new_busy_end TIME;
  v_conflict_count INTEGER;
BEGIN
  
  -- Calculate busy end time (Including the cleaning/padding intervals)
  v_new_busy_end := p_appointment_time + ((p_duration_minutes + p_padding_minutes) || ' minutes')::INTERVAL;
  
  -- Perform absolute ROW COUNT regardless of user identity
  SELECT COUNT(*) INTO v_conflict_count
  FROM appointments a
  JOIN services s ON a.service_id = s.id
  WHERE a.barber_id = p_barber_id
    AND a.appointment_date = p_appointment_date
    AND a.status IN ('confirmed', 'pending')
    AND a.id != COALESCE(p_exclude_appointment_id, '00000000-0000-0000-0000-000000000000'::UUID)
    AND (
      -- Collision 1: New appointment starts before existing appointment ends
      p_appointment_time < (
        COALESCE(a.appointment_end_time, a.appointment_time + (COALESCE(s.duration_minutes, 60) || ' minutes')::INTERVAL)
        + (COALESCE(s.padding_minutes, 0) || ' minutes')::INTERVAL
      )
      AND
      -- Collision 2: New appointment ends after existing appointment starts
      v_new_busy_end > a.appointment_time
    )
  FOR UPDATE NOWAIT;
  
  RETURN v_conflict_count > 0;
  
EXCEPTION
  WHEN lock_not_available THEN
    -- If locked by another parallel request (Atomic Lock from create_public_appointment), consider it busy instantly
    RETURN TRUE;
END;
$$;


ALTER FUNCTION "public"."check_appointment_conflict"("p_barber_id" "uuid", "p_appointment_date" "date", "p_appointment_time" time without time zone, "p_duration_minutes" integer, "p_padding_minutes" integer, "p_exclude_appointment_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."check_appointment_rate_limit"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
    client_ip text;
BEGIN
    BEGIN
        client_ip := current_setting('request.headers', true)::json->>'x-forwarded-for';
    EXCEPTION WHEN OTHERS THEN
        client_ip := NULL;
    END;

    IF (auth.jwt()->>'role') = 'service_role' THEN
        RETURN NEW;
    END IF;

    IF client_ip IS NULL THEN
        client_ip := COALESCE(auth.uid()::text, 'anon');
    ELSE
        client_ip := split_part(client_ip, ',', 1);
    END IF;

    IF auth.uid() IS NOT NULL THEN
        IF EXISTS (SELECT 1 FROM barbershops WHERE owner_id = auth.uid() AND id = NEW.barbershop_id) THEN
            RETURN NEW;
        END IF;
         IF NEW.barber_id IS NOT NULL AND EXISTS (SELECT 1 FROM barbers WHERE id = NEW.barber_id AND user_id = auth.uid()) THEN
            RETURN NEW;
        END IF;
    END IF;

    IF NOT check_rate_limit('appt_limit:' || client_ip, 5, 3600) THEN
        RAISE EXCEPTION 'Limite de agendamentos excedido. Tente novamente em uma hora.';
    END IF;

    RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."check_appointment_rate_limit"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."check_barber_limit"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
  v_plan text;
  v_count integer;
  v_limit integer;
BEGIN
  -- OTIMIZAÇÃO DE "SWAP" E PERFORMANCE (MASTERPIECE):
  -- 1. Usamos CONSTRAINT TRIGGER ... DEFERRED.
  --    Isso permite que você remova um barbeiro e adicione outro na MESMA transação sem se preocupar com a ordem.
  --    (Ex: Inserir Novo -> Count=2 (Erro?) -> Deletar Velho -> Commit -> Trigger Roda -> Count=1 (Sucesso!)).
  --    Isso elimina "gargalos de fluxo" onde o dev precisa ordenar as operações perfeitamente.
  
  -- Lock na Barbearia (Non-blocking FKs)
  PERFORM 1 FROM public.barbershops WHERE id = NEW.barbershop_id FOR NO KEY UPDATE;

  -- Obter o plano
  SELECT subscription_plan INTO v_plan
  FROM public.barbershops
  WHERE id = NEW.barbershop_id;

  IF v_plan = 'premium' THEN
    v_limit := 15;
  ELSIF v_plan = 'professional' THEN
    v_limit := 1;
  ELSE
    v_limit := 1;
  END IF;

  -- Contar barbeiros ATIVOS
  SELECT count(*) INTO v_count
  FROM public.barbers
  WHERE barbershop_id = NEW.barbershop_id
  AND is_active = true;

  IF v_count > v_limit THEN
    RAISE EXCEPTION 'Limite de barbeiros atingido para o plano %. Limite: %', v_plan, v_limit;
  END IF;

  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."check_barber_limit"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."check_barber_limits"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
DECLARE
  v_plan text;
  v_current_count integer;
  v_limit integer;
BEGIN
  -- Buscar plano da barbearia
  SELECT subscription_plan INTO v_plan
  FROM public.barbershops
  WHERE id = NEW.barbershop_id;

  -- Contar barbeiros ATIVOS atuais (excluindo este se for update, mas aqui Ã© insert)
  SELECT COUNT(*) INTO v_current_count
  FROM public.barbers
  WHERE barbershop_id = NEW.barbershop_id
  AND is_active = true;
  
  -- Para UPDATE ativando um barbeiro, tambÃ©m conta.
  
  v_limit := public.get_plan_barber_limit(v_plan);

  IF (v_current_count >= v_limit) THEN
     RAISE EXCEPTION 'Limite de profissionais atingido para o plano %. Atualize sua assinatura para adicionar mais.', COALESCE(v_plan, 'Starter');
  END IF;

  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."check_barber_limits"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."check_default_partition_health"() RETURNS TABLE("size_mb" bigint, "row_count" bigint, "alert_level" "text", "recommendation" "text")
    LANGUAGE "plpgsql"
    AS $$
DECLARE
    v_size_bytes BIGINT;
    v_row_count BIGINT;
BEGIN
    -- Get size and row count
    SELECT pg_total_relation_size('public.audit_logs_default') INTO v_size_bytes;
    SELECT COUNT(*) FROM public.audit_logs_default INTO v_row_count;
    
    -- Return health metrics
    RETURN QUERY SELECT 
        v_size_bytes / 1024 / 1024 AS size_mb,
        v_row_count,
        CASE 
            WHEN v_size_bytes > 500 * 1024 * 1024 THEN 'CRITICAL'  -- > 500 MB
            WHEN v_size_bytes > 100 * 1024 * 1024 THEN 'WARNING'   -- > 100 MB
            WHEN v_row_count > 10000 THEN 'WARNING'
            ELSE 'OK'
        END AS alert_level,
        CASE 
            WHEN v_size_bytes > 500 * 1024 * 1024 THEN 'Immediate action required: Investigate logs in default partition'
            WHEN v_size_bytes > 100 * 1024 * 1024 THEN 'Review logs in default partition, may indicate missing partitions'
            WHEN v_row_count > 10000 THEN 'High row count in default partition, check for date issues'
            ELSE 'Default partition is healthy'
        END AS recommendation;
END;
$$;


ALTER FUNCTION "public"."check_default_partition_health"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."check_mfa_compliance"() RETURNS boolean
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'auth', 'extensions'
    AS $$
DECLARE
  v_user_id uuid := auth.uid();
  v_factors_count integer;
  v_aal text;
  v_jwt_claims jsonb;
BEGIN
  -- Se nÃ£o logado, false (ou true dependendo da sua politica de guest)
  -- Para RLS de tabelas privadas, retornar false Ã© mais seguro.
  IF v_user_id IS NULL THEN
    RETURN false;
  END IF;

  -- Obter AAL direto do JWT Claims
  -- (Anteriormente estava em uma funÃ§Ã£o separada, agora inlinamos para evitar erro 42501)
  BEGIN
    v_jwt_claims := current_setting('request.jwt.claims', true)::jsonb;
    v_aal := COALESCE(v_jwt_claims ->> 'aal', 'aal1');
  EXCEPTION WHEN OTHERS THEN
    v_aal := 'aal1'; -- Fallback seguro
  END;

  -- Contar fatores verificados do usuÃ¡rio
  -- Nota: auth.mfa_factors Ã© legÃ­vel por SECURITY DEFINER
  SELECT COUNT(*) INTO v_factors_count
  FROM auth.mfa_factors
  WHERE user_id = v_user_id AND status = 'verified';

  -- LÃ³gica de Blindagem:
  
  -- CenÃ¡rio A: UsuÃ¡rio NÃƒO tem MFA configurado
  IF v_factors_count = 0 THEN
    -- Permite acesso AAL1 (Senha simples)
    RETURN true; 
  END IF;

  -- CenÃ¡rio B: UsuÃ¡rio TEM MFA configurado
  IF v_factors_count > 0 THEN
    -- Se ele tem MFA, EXIGE que a sessÃ£o seja 'aal2' (que prova que ele usou o MFA)
    IF v_aal = 'aal2' THEN
      RETURN true;
    ELSE
      -- Tentativa de acesso apenas com senha em uma conta protegida -> BLOQUEAR
      -- RAISE LOG 'Tentativa de acesso AAL1 em conta MFA: %', v_user_id;
      RETURN false;
    END IF;
  END IF;

  RETURN false;
END;
$$;


ALTER FUNCTION "public"."check_mfa_compliance"() OWNER TO "postgres";


COMMENT ON FUNCTION "public"."check_mfa_compliance"() IS 'Valida se a sessÃ£o atual cumpre os requisitos de MFA. Se o usuÃ¡rio ativou MFA, a sessÃ£o tem que ser aal2.';



CREATE OR REPLACE FUNCTION "public"."check_mfa_recovery_rate_limit"("p_user_id" "uuid", "p_ip" "inet" DEFAULT NULL::"inet") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'pg_catalog', 'public', 'pg_temp'
    AS $$
DECLARE
  v_user_attempts  INTEGER;
  v_ip_attempts    INTEGER;
BEGIN
  -- Contar tentativas FALHAS deste usuário nos últimos 15 minutos
  SELECT COUNT(*) INTO v_user_attempts
  FROM public.mfa_recovery_attempts
  WHERE user_id = p_user_id
    AND attempted_at > NOW() - INTERVAL '15 minutes'
    AND succeeded = FALSE;

  -- Contar tentativas deste IP nos últimos 15 minutos (multi-account attack)
  IF p_ip IS NOT NULL THEN
    SELECT COUNT(*) INTO v_ip_attempts
    FROM public.mfa_recovery_attempts
    WHERE ip_address = p_ip
      AND attempted_at > NOW() - INTERVAL '15 minutes'
      AND succeeded = FALSE;
  ELSE
    v_ip_attempts := 0;
  END IF;

  -- Limites: 5 tentativas por conta OU 10 por IP em 15 minutos
  IF v_user_attempts >= 5 THEN
    RAISE EXCEPTION 'RECOVERY_RATE_LIMIT_USER'
      USING ERRCODE = 'P0429',
            HINT    = 'Too many failed recovery attempts for this account. Try again in 15 minutes.';
  END IF;

  IF v_ip_attempts >= 10 THEN
    RAISE EXCEPTION 'RECOVERY_RATE_LIMIT_IP'
      USING ERRCODE = 'P0429',
            HINT    = 'Too many requests from this IP. Try again in 15 minutes.';
  END IF;
END;
$$;


ALTER FUNCTION "public"."check_mfa_recovery_rate_limit"("p_user_id" "uuid", "p_ip" "inet") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."check_rate_limit"("p_key" "text", "p_limit" integer, "p_window_seconds" integer, "p_function_name" "text" DEFAULT 'global'::"text") RETURNS boolean
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
    r_count int;
    is_allowed boolean;
    v_identifier text;
BEGIN
    -- Input sanitization
    v_identifier := p_key;

    -- Cleanup old records (Probabilistic 5%)
    IF (random() < 0.05) THEN
        DELETE FROM public.rate_limits 
        WHERE window_start < now() - (p_window_seconds || ' seconds')::interval;
    END IF;

    -- Upsert Logic
    INSERT INTO public.rate_limits (identifier, function_name, count, window_start)
    VALUES (v_identifier, p_function_name, 1, now())
    ON CONFLICT (identifier, function_name) DO UPDATE
    SET
        count = CASE 
            WHEN rate_limits.window_start < (now() - (p_window_seconds || ' seconds')::interval) THEN 1 
            ELSE rate_limits.count + 1 
        END,
        window_start = CASE 
            WHEN rate_limits.window_start < (now() - (p_window_seconds || ' seconds')::interval) THEN now() 
            ELSE rate_limits.window_start 
        END
    RETURNING count INTO r_count;

    is_allowed := r_count <= p_limit;
    RETURN is_allowed;
END;
$$;


ALTER FUNCTION "public"."check_rate_limit"("p_key" "text", "p_limit" integer, "p_window_seconds" integer, "p_function_name" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."check_subscription_before_delete"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  -- Se a assinatura estÃ¡ ativa, BLOQUEAR deleÃ§Ã£o.
  IF OLD.subscription_status = 'active' OR OLD.subscription_status = 'trialing' THEN
     RAISE EXCEPTION 'ZOMBIE BILL PROTECTION: A barbearia "%" possui assinatura ATIVA. Cancele no Painel/Stripe antes de deletar, para evitar cobranÃ§as indevidas.', OLD.name;
  END IF;

  RETURN OLD;
END;
$$;


ALTER FUNCTION "public"."check_subscription_before_delete"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."clean_html"("p_text" "text") RETURNS "text"
    LANGUAGE "plpgsql" IMMUTABLE
    AS $$
BEGIN
    -- Regex to strip tags (Simple but effective for <script>, <iframe> etc)
    RETURN regexp_replace(p_text, '<[^>]+>', '', 'g');
END;
$$;


ALTER FUNCTION "public"."clean_html"("p_text" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."clean_metadata_input"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
    -- Basic cleaning for common text fields to prevent second-order issues
    IF TG_TABLE_NAME = 'customers' THEN
        NEW.name := trim(substring(NEW.name from 1 for 100));
    ELSIF TG_TABLE_NAME = 'appointments' THEN
        NEW.notes := trim(substring(NEW.notes from 1 for 1000));
    END IF;
    RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."clean_metadata_input"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."clean_storage_orphans"() RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
    v_orphans_found INT := 0;
    v_result JSONB;
BEGIN
    -- This function is a FOUNDATION. 
    -- It identifies objects in 'logos', 'avatars', 'barber-portfolios' 
    -- that don't have matching IDs in the application tables.

    -- LOGOS: Path is {user_id}/{filename}. We check if user_id exists in profiles/barbershops.
    -- (Logic will be refined as specific cleanup criteria are finalized).
    
    -- For now, we log that the process was initiated.
    PERFORM public.log_sovereign_event(
        'storage_hygiene_initiated',
        'info',
        'Storage orphan scan started.'
    );

    v_result := jsonb_build_object(
        'status', 'success',
        'message', 'Hygiene scan completed (Foundation Active)',
        'timestamp', NOW()
    );

    RETURN v_result;
END;
$$;


ALTER FUNCTION "public"."clean_storage_orphans"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."cleanup_audit_logs"() RETURNS integer
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'pg_catalog', 'public', 'pg_temp'
    AS $$
DECLARE
  v_affected INTEGER;
BEGIN
  -- Login attempts: 90 dias (conforme COMP-001)
  DELETE FROM public.login_attempts
  WHERE attempted_at < NOW() - INTERVAL '90 days';

  GET DIAGNOSTICS v_affected = ROW_COUNT;
  RETURN v_affected;
END;
$$;


ALTER FUNCTION "public"."cleanup_audit_logs"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."cleanup_mfa_recovery_attempts"() RETURNS integer
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'pg_catalog', 'public', 'pg_temp'
    AS $$
DECLARE
  v_deleted INTEGER;
BEGIN
  -- Remover tentativas com mais de 24 horas
  DELETE FROM public.mfa_recovery_attempts
  WHERE attempted_at < NOW() - INTERVAL '24 hours';

  GET DIAGNOSTICS v_deleted = ROW_COUNT;
  RETURN v_deleted;
END;
$$;


ALTER FUNCTION "public"."cleanup_mfa_recovery_attempts"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."cleanup_old_audit_logs"() RETURNS "void"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_retention_days integer := 180;
  v_cutoff_date timestamp;
BEGIN
  v_cutoff_date := NOW() - (v_retention_days || ' days')::interval;
  
  DELETE FROM public.audit_logs
  WHERE created_at < v_cutoff_date;
END;
$$;


ALTER FUNCTION "public"."cleanup_old_audit_logs"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."cleanup_old_csp_violations"() RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
  DELETE FROM public.csp_violations
  WHERE created_at < NOW() - INTERVAL '30 days';
END;
$$;


ALTER FUNCTION "public"."cleanup_old_csp_violations"() OWNER TO "postgres";


COMMENT ON FUNCTION "public"."cleanup_old_csp_violations"() IS 'Limpeza automática de violações CSP antigas (>30 dias).
SECURITY DEFINER + search_path fixo previnem hijacking attacks.';



CREATE OR REPLACE FUNCTION "public"."cleanup_old_logs"() RETURNS integer
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_retention_days integer := 90;
  v_cutoff_date timestamp;
  v_deleted_count integer;
BEGIN
  v_cutoff_date := NOW() - (v_retention_days || ' days')::interval;
  
  DELETE FROM public.audit_logs
  WHERE created_at < v_cutoff_date;
  
  GET DIAGNOSTICS v_deleted_count = ROW_COUNT;
  
  RETURN v_deleted_count;
END;
$$;


ALTER FUNCTION "public"."cleanup_old_logs"() OWNER TO "postgres";


COMMENT ON FUNCTION "public"."cleanup_old_logs"() IS 'Limpa logs: permission_audit_log (1 ano), security_events (90 dias low/medium, 1 ano critical/high)';



CREATE OR REPLACE FUNCTION "public"."cleanup_old_rate_limits"() RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
  DELETE FROM rate_limits 
  WHERE window_start < NOW() - INTERVAL '2 hours';
END;
$$;


ALTER FUNCTION "public"."cleanup_old_rate_limits"() OWNER TO "postgres";


COMMENT ON FUNCTION "public"."cleanup_old_rate_limits"() IS 'Limpeza automática de registros antigos de rate limiting (>2h).
SECURITY DEFINER + search_path fixo previnem hijacking attacks.';



CREATE OR REPLACE FUNCTION "public"."cleanup_referential_integrity"() RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
    v_disable_crons BOOLEAN;
BEGIN
    -- Check Kill Switch
    SELECT (value::TEXT = 'true') INTO v_disable_crons 
    FROM public.system_settings 
    WHERE key = 'disable_crons';
    
    IF v_disable_crons THEN
        RETURN;
    END IF;

    -- A. Audit Logs (Already Tiered)
    DELETE FROM public.audit_logs
    WHERE created_at < NOW() - INTERVAL '90 days'
    AND level IN ('info', 'warning');

    DELETE FROM public.audit_logs
    WHERE created_at < NOW() - INTERVAL '1 year'
    AND level = 'critical';

    -- B. Subscription Logs
    IF EXISTS (SELECT FROM pg_tables WHERE schemaname = 'public' AND tablename = 'subscription_logs') THEN
        DELETE FROM public.subscription_logs
        WHERE created_at < NOW() - INTERVAL '1 year';
    END IF;

    -- C. [NEW] Cron Health Logs (High Volume)
    IF EXISTS (SELECT FROM pg_tables WHERE schemaname = 'public' AND tablename = 'cron_health_logs') THEN
        -- Keep only 30 days of health history
        DELETE FROM public.cron_health_logs
        WHERE created_at < NOW() - INTERVAL '30 days';
    END IF;

    -- D. [NEW] Webhook Events (V19)
    IF EXISTS (SELECT FROM pg_tables WHERE schemaname = 'public' AND tablename = 'webhook_events') THEN
        -- Keep completed/failed events for only 7 days
        DELETE FROM public.webhook_events
        WHERE created_at < NOW() - INTERVAL '7 days'
        AND status IN ('completed', 'failed');
    END IF;

    -- Log Cleanup Execution
    INSERT INTO public.audit_logs (action, level, description, metadata)
    VALUES ('system_cleanup', 'info', 'Extended retention policy executed successfully.', jsonb_build_object('timestamp', NOW()));

END;
$$;


ALTER FUNCTION "public"."cleanup_referential_integrity"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."consolidate_bi_logs"("p_batch_size" integer DEFAULT 5000) RETURNS TABLE("rows_processed" integer, "has_more" boolean)
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_processed integer;
  v_total_pending integer;
BEGIN
  WITH moved_events AS (
    DELETE FROM public.bi_events_buffer
    WHERE id IN (
      SELECT id 
      FROM public.bi_events_buffer 
      ORDER BY created_at 
      LIMIT p_batch_size
    )
    RETURNING *
  )
  INSERT INTO public.bi_events_consolidated
  SELECT * FROM moved_events;
  
  GET DIAGNOSTICS v_processed = ROW_COUNT;
  
  SELECT COUNT(*) INTO v_total_pending
  FROM public.bi_events_buffer;
  
  RETURN QUERY SELECT v_processed, (v_total_pending > 0);
END;
$$;


ALTER FUNCTION "public"."consolidate_bi_logs"("p_batch_size" integer) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."create_appointment_v3"("p_customer_phone" "text", "p_customer_name" "text", "p_customer_email" "text", "p_date" "date", "p_time" time without time zone, "p_barber_id" "uuid", "p_service_id" "uuid", "p_barbershop_id" "uuid", "p_notes" "text") RETURNS json
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_customer_id uuid;
  v_appointment_id uuid;
  v_token text;
  v_existing_appointment_id uuid;
  v_barbershop_active boolean;
  v_service_duration integer;
  v_has_conflict boolean;
  v_is_owner boolean;
  v_barber_valid boolean;
  v_phone_clean text;
  v_phone_final text;
  v_now_br timestamp;
BEGIN
  -- 0. TEMPORAL (No Time Travel) - FIXED V3.2 (Sovereign Time)
  -- Uses explicit DB-centric time, removing helper dependency.
  
  v_now_br := (CURRENT_TIMESTAMP AT TIME ZONE 'America/Sao_Paulo');
  
  -- Validation: Past Date
  IF p_date < v_now_br::date THEN 
    RAISE EXCEPTION 'Não é possível agendar para o passado.'; 
  END IF;

  -- Validation: Past Time (Today)
  IF p_date = v_now_br::date AND p_time < v_now_br::time THEN
     RAISE EXCEPTION 'Não é possível agendar um horário que já passou.';
  END IF;

  -- 1. AUTORIZAÇÃO (Owner Only)
  SELECT (owner_id = auth.uid()) INTO v_is_owner FROM barbershops WHERE id = p_barbershop_id;
  IF v_is_owner IS NULL OR v_is_owner = false THEN RAISE EXCEPTION 'Acesso negado.'; END IF;

  -- 1.1 HIGIENIZAÇÃO (Phone Normalization V2)
  v_phone_clean := REGEXP_REPLACE(p_customer_phone, '\D', '', 'g');
  v_phone_clean := REGEXP_REPLACE(v_phone_clean, '^0+', '');
  
  IF LENGTH(v_phone_clean) <= 11 THEN
     v_phone_final := '+55' || v_phone_clean;
  ELSE
     v_phone_final := '+' || v_phone_clean;
  END IF;

  -- 2. NEGÓCIO (Active Shop)
  SELECT (subscription_status != 'cancelled' AND is_active = true) INTO v_barbershop_active
  FROM barbershops WHERE id = p_barbershop_id;
  IF v_barbershop_active IS NULL OR v_barbershop_active = false THEN RAISE EXCEPTION 'Barbearia inativa.'; END IF;

  -- 3. INTEGRIDADE
  SELECT EXISTS(SELECT 1 FROM barbers WHERE id = p_barber_id AND barbershop_id = p_barbershop_id AND is_active = true) 
  INTO v_barber_valid;
  IF NOT v_barber_valid THEN RAISE EXCEPTION 'Barbeiro inválido.'; END IF;

  SELECT duration_minutes INTO v_service_duration FROM services 
  WHERE id = p_service_id AND barbershop_id = p_barbershop_id AND is_active = true;
  IF v_service_duration IS NULL THEN RAISE EXCEPTION 'Serviço inválido.'; END IF;

  -- 4. CONFLITO (Duration Logic)
  SELECT check_appointment_conflict(p_barber_id, p_date, p_time, v_service_duration) INTO v_has_conflict;
  IF v_has_conflict THEN RAISE EXCEPTION 'Horário indisponível (Conflito de duração).'; END IF;

  -- 5. LOCK (Atomic)
  SELECT id INTO v_existing_appointment_id FROM appointments
  WHERE barber_id = p_barber_id AND appointment_date = p_date AND appointment_time = p_time
  AND status NOT IN ('cancelled', 'no_show') FOR UPDATE NOWAIT; 

  IF v_existing_appointment_id IS NOT NULL THEN RAISE EXCEPTION 'Horário reservado.'; END IF;

  -- 6. ATOMIC CUSTOMER (Normalized Phone)
  INSERT INTO customers (barbershop_id, name, phone, email) 
  VALUES (p_barbershop_id, TRIM(p_customer_name), v_phone_final, TRIM(LOWER(p_customer_email)))
  ON CONFLICT (barbershop_id, phone) DO UPDATE 
  SET name = TRIM(p_customer_name), email = COALESCE(TRIM(LOWER(p_customer_email)), customers.email)
  RETURNING id INTO v_customer_id;

  -- 7. INSERT APPOINTMENT
  INSERT INTO appointments (barbershop_id, customer_id, barber_id, service_id, appointment_date, appointment_time, notes, status)
  VALUES (p_barbershop_id, v_customer_id, p_barber_id, p_service_id, p_date, p_time, TRIM(p_notes), 'confirmed')
  RETURNING id INTO v_appointment_id;

  SELECT generate_appointment_token(v_appointment_id) INTO v_token;
  RETURN json_build_object('appointment_id', v_appointment_id, 'management_token', v_token, 'status', 'confirmed');

EXCEPTION
  WHEN lock_not_available THEN RAISE EXCEPTION 'Erro de Concorrência: Agendamento simultâneo detectado.';
  WHEN unique_violation THEN RAISE EXCEPTION 'Horário já reservado.';
  WHEN OTHERS THEN RAISE EXCEPTION 'Falha no agendamento: %', SQLERRM;
END;
$$;


ALTER FUNCTION "public"."create_appointment_v3"("p_customer_phone" "text", "p_customer_name" "text", "p_customer_email" "text", "p_date" "date", "p_time" time without time zone, "p_barber_id" "uuid", "p_service_id" "uuid", "p_barbershop_id" "uuid", "p_notes" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."create_barbershop_with_setup"("p_owner_id" "uuid", "p_name" "text", "p_slug" "text", "p_phone" "text" DEFAULT NULL::"text", "p_address" "text" DEFAULT NULL::"text", "p_description" "text" DEFAULT NULL::"text") RETURNS json
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
        DECLARE
          v_barbershop_id UUID;
          v_default_barber_id UUID;
          v_default_service_id UUID;
        BEGIN
          -- Validar entrada
          IF p_owner_id IS NULL OR p_name IS NULL OR p_slug IS NULL THEN
            RAISE EXCEPTION 'Owner ID, nome e slug são obrigatórios';
          END IF;
          
          -- Verificar duplicidade
          IF EXISTS (SELECT 1 FROM barbershops WHERE slug = p_slug) THEN
            RAISE EXCEPTION 'Esta URL já está em uso. Escolha outra.';
          END IF;
          
          IF EXISTS (SELECT 1 FROM barbershops WHERE owner_id = p_owner_id) THEN
            RAISE EXCEPTION 'Você já possui uma barbearia cadastrada';
          END IF;
          
          -- ============================================
          -- TRANSAÇÃO
          -- ============================================
          
          -- 1. Criar barbearia
          INSERT INTO barbershops (
            owner_id, name, slug, phone, address, description, 
            subscription_plan, subscription_status, trial_ends_at
          ) VALUES (
            p_owner_id, p_name, p_slug, p_phone, p_address, p_description,
            'free', 'trial', NOW() + INTERVAL '3 days'
          )
          RETURNING id INTO v_barbershop_id;
          
          -- 2. FIX: Insert/Update Role to Owner (WITH BYPASS)
          -- Set bypass flag for the trigger
          PERFORM set_config('app.bypass_role_guard', 'on', true);
          
          INSERT INTO public.user_roles (user_id, role)
          VALUES (p_owner_id, 'owner')
          ON CONFLICT (user_id) DO UPDATE SET role = 'owner';
          
          -- 3. Criar barbeiro padrão
          INSERT INTO barbers (barbershop_id, name, is_active, commission_percentage)
          VALUES (v_barbershop_id, 'Barbeiro Principal', TRUE, 0.0)
          RETURNING id INTO v_default_barber_id;
          
          -- 4. Criar serviços básicos
          INSERT INTO services (barbershop_id, name, price, duration_minutes, is_active)
          VALUES (v_barbershop_id, 'Corte', 30.00, 30, TRUE)
          RETURNING id INTO v_default_service_id;
          
          INSERT INTO services (barbershop_id, name, price, duration_minutes, is_active)
          VALUES (v_barbershop_id, 'Barba', 20.00, 20, TRUE);
          
          INSERT INTO services (barbershop_id, name, price, duration_minutes, is_active)
          VALUES (v_barbershop_id, 'Corte + Barba', 45.00, 50, TRUE);
          
          RETURN json_build_object(
            'success', TRUE,
            'barbershop_id', v_barbershop_id,
            'message', 'Barbearia criada com sucesso!'
          );
          
        EXCEPTION
          WHEN unique_violation THEN
            RAISE EXCEPTION 'Esta URL já está em uso.';
          WHEN OTHERS THEN
            RAISE EXCEPTION 'Erro ao criar barbearia: %', SQLERRM;
        END;
        $$;


ALTER FUNCTION "public"."create_barbershop_with_setup"("p_owner_id" "uuid", "p_name" "text", "p_slug" "text", "p_phone" "text", "p_address" "text", "p_description" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."create_public_appointment"("p_barbershop_slug" "text", "p_customer_name" "text", "p_customer_phone" "text", "p_customer_email" "text", "p_barber_id" "uuid", "p_service_id" "uuid", "p_appointment_date" "date", "p_appointment_time" time without time zone, "p_notes" "text") RETURNS json
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_barbershop_id uuid;
  v_barbershop_name text;
  v_barbershop_address text;
  v_customer_id uuid;
  v_appointment_id uuid;
  v_service_duration integer;
  v_service_padding integer;
  v_service_name text;
  v_barber_name text;
  v_has_conflict boolean;
  v_token text;
  v_old_appointment_id uuid;
  v_cancelled_count integer := 0;
  v_current_user_id uuid;
  v_is_customer_owner boolean := false;
  v_queue_payload jsonb;
BEGIN
  -- 1. INPUT VALIDATION
  IF p_customer_name IS NULL OR p_customer_phone IS NULL THEN
    RAISE EXCEPTION 'ERR_MISSING_FIELDS: Nome e telefone são obrigatórios';
  END IF;

  -- Obter user_id atual (se cliente está logado)
  v_current_user_id := auth.uid();

  -- 2. RATE LIMITING
  IF v_current_user_id IS NULL THEN
      IF NOT check_rate_limit('rpc_appt_phone:' || p_customer_phone, 5, 3600) THEN
          RAISE EXCEPTION 'ERR_RATE_LIMIT: Muitas tentativas. Aguarde 1 hora.';
      END IF;
  END IF;

  -- 3. BARBERSHOP VALIDATION
  SELECT id, name, address INTO v_barbershop_id, v_barbershop_name, v_barbershop_address
  FROM public.barbershops
  WHERE slug = p_barbershop_slug 
    AND subscription_status != 'cancelled';
  
  IF v_barbershop_id IS NULL THEN
    RAISE EXCEPTION 'ERR_BARBERSHOP_NOT_FOUND: Barbearia não encontrada ou inativa';
  END IF;

  -- 4. SERVICE VALIDATION
  SELECT 
    duration_minutes,
    padding_minutes,
    name
  INTO 
    v_service_duration,
    v_service_padding,
    v_service_name
  FROM public.services
  WHERE id = p_service_id;

  IF v_service_duration IS NULL THEN
    RAISE EXCEPTION 'ERR_SERVICE_NOT_FOUND: Serviço não encontrado no catálogo';
  END IF;

  -- 5. BARBER VALIDATION
  SELECT name INTO v_barber_name FROM public.barbers WHERE id = p_barber_id;
  IF v_barber_name IS NULL THEN
     RAISE EXCEPTION 'ERR_BARBER_NOT_FOUND: Barbeiro não encontrado';
  END IF;
  
  -- Default padding safe
  IF v_service_padding IS NULL THEN v_service_padding := 0; END IF;

  -- 6. CONFLICT CHECK (CRITICAL)
  SELECT check_appointment_conflict(
    p_barber_id,
    p_appointment_date,
    p_appointment_time,
    v_service_duration,
    v_service_padding
  ) INTO v_has_conflict;

  IF v_has_conflict THEN
    RAISE EXCEPTION 'ERR_SLOT_CONFLICT: Horário indisponível (reservado ou bloqueado)';
  END IF;

  -- 7. CUSTOMER UPSERT
  IF v_current_user_id IS NOT NULL THEN
    SELECT id INTO v_customer_id
    FROM public.customers
    WHERE barbershop_id = v_barbershop_id
      AND user_id = v_current_user_id
    LIMIT 1;
    
    IF v_customer_id IS NULL THEN
      SELECT id INTO v_customer_id
      FROM public.customers
      WHERE barbershop_id = v_barbershop_id
        AND phone = p_customer_phone;
    END IF;
  ELSE
    SELECT id INTO v_customer_id
    FROM public.customers
    WHERE barbershop_id = v_barbershop_id
      AND phone = p_customer_phone;
  END IF;
  
  IF v_customer_id IS NULL THEN
    INSERT INTO public.customers (barbershop_id, name, phone, email, user_id)
    VALUES (
      v_barbershop_id, 
      p_customer_name, 
      p_customer_phone, 
      p_customer_email,
      v_current_user_id
    )
    RETURNING id INTO v_customer_id;
    
    IF v_current_user_id IS NOT NULL THEN
       v_is_customer_owner := true;
    END IF;
  ELSE
    UPDATE public.customers
    SET 
      name = p_customer_name,
      email = COALESCE(p_customer_email, email),
      user_id = COALESCE(user_id, v_current_user_id),
      updated_at = NOW()
    WHERE id = v_customer_id;
    
    IF v_current_user_id IS NOT NULL THEN
       PERFORM 1 FROM public.customers WHERE id = v_customer_id AND user_id = v_current_user_id;
       IF FOUND THEN
         v_is_customer_owner := true;
       END IF;
    END IF;
  END IF;

  -- 8. AUTO-CANCELLATION
  IF v_current_user_id IS NOT NULL AND v_is_customer_owner IS TRUE THEN
      FOR v_old_appointment_id IN 
        SELECT id 
        FROM public.appointments
        WHERE customer_id = v_customer_id
          AND barbershop_id = v_barbershop_id
          AND status IN ('confirmed', 'pending')
          AND (
            appointment_date > CURRENT_DATE
            OR (appointment_date = CURRENT_DATE AND appointment_time > CURRENT_TIME)
          )
      LOOP
        UPDATE public.appointments
        SET 
          status = 'cancelled',
          updated_at = NOW()
        WHERE id = v_old_appointment_id;

        INSERT INTO public.appointment_cancellations (
          appointment_id,
          cancelled_by,
          cancelled_by_user_id,
          cancellation_reason,
          cancelled_at
        ) VALUES (
          v_old_appointment_id,
          'system',
          v_current_user_id,
          'Cliente criou novo agendamento - cancelamento automático (Security Check Passed)',
          NOW()
        );

        v_cancelled_count := v_cancelled_count + 1;
      END LOOP;
  END IF;

  -- 9. CREATE APPOINTMENT
  INSERT INTO public.appointments (
    barbershop_id,
    customer_id,
    barber_id,
    service_id,
    appointment_date,
    appointment_time,
    notes,
    status,
    whatsapp_sent
  ) VALUES (
    v_barbershop_id,
    v_customer_id,
    p_barber_id,
    p_service_id,
    p_appointment_date,
    p_appointment_time,
    p_notes,
    'confirmed',
    false
  )
  RETURNING id INTO v_appointment_id;

  -- 10. GENERATE TOKEN
  SELECT generate_appointment_token(v_appointment_id) INTO v_token;

  -- 11. ASYNC MESSAGING (QUEUE)
  -- Insert into queue immediately (Atomic Transaction)
  v_queue_payload := jsonb_build_object(
      'appointmentId', v_appointment_id,
      'type', 'confirmation',
      'customerPhone', p_customer_phone,
      'customerName', p_customer_name,
      'barberName', v_barber_name,
      'serviceName', v_service_name,
      'barbershopName', v_barbershop_name,
      'barbershopAddress', v_barbershop_address,
      'barbershopId', v_barbershop_id,
      'appointmentDate', p_appointment_date,
      'appointmentTime', p_appointment_time,
      'managementUrl', current_setting('request.headers', true)::json->>'origin' || '/gerenciar/' || v_token
  ) || jsonb_build_object('managementToken', v_token);

  INSERT INTO public.notification_queue (
      appointment_id,
      type,
      payload,
      status
  ) VALUES (
      v_appointment_id,
      'confirmation',
      v_queue_payload,
      'pending'
  );

  RETURN json_build_object(
    'success', true,
    'appointment_id', v_appointment_id,
    'management_token', v_token,
    'cancelled_old_appointments', v_cancelled_count,
    'message', CASE 
      WHEN v_cancelled_count > 0 
      THEN 'Agendamento realizado! ' || v_cancelled_count || ' agendamento(s) anterior(es) cancelado(s).'
      ELSE 'Agendamento realizado com sucesso!'
    END
  );

END;
$$;


ALTER FUNCTION "public"."create_public_appointment"("p_barbershop_slug" "text", "p_customer_name" "text", "p_customer_phone" "text", "p_customer_email" "text", "p_barber_id" "uuid", "p_service_id" "uuid", "p_appointment_date" "date", "p_appointment_time" time without time zone, "p_notes" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."create_public_appointment"("p_barbershop_slug" "text" DEFAULT NULL::"text", "p_customer_name" "text" DEFAULT NULL::"text", "p_customer_phone" "text" DEFAULT NULL::"text", "p_customer_email" "text" DEFAULT NULL::"text", "p_barber_id" "uuid" DEFAULT NULL::"uuid", "p_service_id" "uuid" DEFAULT NULL::"uuid", "p_appointment_date" "date" DEFAULT NULL::"date", "p_appointment_time" time without time zone DEFAULT NULL::time without time zone, "p_notes" "text" DEFAULT NULL::"text", "p_barbershop_id" "uuid" DEFAULT NULL::"uuid") RETURNS json
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'extensions'
    AS $$
DECLARE
  v_barbershop_id uuid;
  v_barbershop_name text;
  v_barbershop_address text;
  v_customer_id uuid;
  v_appointment_id uuid;
  v_service_duration integer;
  v_service_padding integer;
  v_service_name text;
  v_barber_name text;
  v_has_conflict boolean;
  v_token text;
  v_current_user_id uuid;
BEGIN
  IF p_customer_name IS NULL OR p_customer_phone IS NULL THEN
    RAISE EXCEPTION 'ERR_MISSING_FIELDS: Nome e telefone são obrigatórios';
  END IF;

  IF length(p_customer_name) > 100 OR length(COALESCE(p_notes, '')) > 500 THEN
    RAISE EXCEPTION 'ERR_INPUT_TOO_LONG: Nome (max 100) ou notas (max 500) excedidos';
  END IF;

  v_current_user_id := auth.uid();

  SELECT id, name, address INTO v_barbershop_id, v_barbershop_name, v_barbershop_address
  FROM public.barbershops
  WHERE (id = p_barbershop_id OR slug = p_barbershop_slug)
    AND subscription_status != 'cancelled'
    AND deleted_at IS NULL;
  
  IF v_barbershop_id IS NULL THEN
    RAISE EXCEPTION 'ERR_BARBERSHOP_NOT_FOUND: Barbearia não encontrada ou inativa';
  END IF;

  PERFORM 1 FROM public.barbers WHERE id = p_barber_id FOR UPDATE;

  SELECT duration_minutes, padding_minutes, name
  INTO v_service_duration, v_service_padding, v_service_name
  FROM public.services
  WHERE id = p_service_id 
    AND barbershop_id = v_barbershop_id
    AND is_active = true;

  IF v_service_duration IS NULL THEN
    RAISE EXCEPTION 'ERR_SERVICE_NOT_FOUND: Serviço inválido para esta barbearia';
  END IF;

  SELECT name INTO v_barber_name 
  FROM public.barbers 
  WHERE id = p_barber_id 
    AND barbershop_id = v_barbershop_id
    AND is_active = true;

  IF v_barber_name IS NULL THEN
     RAISE EXCEPTION 'ERR_BARBER_NOT_FOUND: Barbeiro inválido para esta barbearia';
  END IF;

  SELECT check_appointment_conflict(
    p_barber_id,
    p_appointment_date,
    p_appointment_time,
    v_service_duration,
    COALESCE(v_service_padding, 0)
  ) INTO v_has_conflict;

  IF v_has_conflict THEN
    RAISE EXCEPTION 'ERR_SLOT_CONFLICT: Horário indisponível';
  END IF;

  SELECT id INTO v_customer_id
  FROM public.customers
  WHERE barbershop_id = v_barbershop_id
    AND phone = p_customer_phone;
  
  IF v_customer_id IS NULL THEN
    INSERT INTO public.customers (barbershop_id, name, phone, email, user_id)
    VALUES (v_barbershop_id, p_customer_name, p_customer_phone, p_customer_email, v_current_user_id)
    RETURNING id INTO v_customer_id;
  ELSE
    UPDATE public.customers
    SET 
      name = p_customer_name,
      email = COALESCE(p_customer_email, email),
      user_id = COALESCE(user_id, v_current_user_id),
      updated_at = NOW()
    WHERE id = v_customer_id;
  END IF;

  INSERT INTO public.appointments (
    barbershop_id, customer_id, barber_id, service_id, 
    appointment_date, appointment_time, notes, status, 
    price, final_amount
  ) 
  SELECT 
    v_barbershop_id, v_customer_id, p_barber_id, p_service_id, 
    p_appointment_date, p_appointment_time, p_notes, 'confirmed',
    price, price
  FROM public.services WHERE id = p_service_id
  RETURNING id INTO v_appointment_id;

  SELECT generate_appointment_token(v_appointment_id) INTO v_token;

  INSERT INTO public.notification_queue (appointment_id, type, status, payload)
  VALUES (v_appointment_id, 'confirmation', 'pending', jsonb_build_object(
      'appointmentId', v_appointment_id,
      'token', v_token,
      'customerName', p_customer_name,
      'barberName', v_barber_name,
      'serviceName', v_service_name,
      'barbershopName', v_barbershop_name,
      'barbershopAddress', v_barbershop_address,
      'appointmentDate', p_appointment_date,
      'appointmentTime', p_appointment_time,
      'customerPhone', p_customer_phone
  ));

  RETURN json_build_object(
    'success', true,
    'appointment_id', v_appointment_id,
    'management_token', v_token
  );
END;
$$;


ALTER FUNCTION "public"."create_public_appointment"("p_barbershop_slug" "text", "p_customer_name" "text", "p_customer_phone" "text", "p_customer_email" "text", "p_barber_id" "uuid", "p_service_id" "uuid", "p_appointment_date" "date", "p_appointment_time" time without time zone, "p_notes" "text", "p_barbershop_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."delete_old_appointments"() RETURNS integer
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'pg_catalog', 'public', 'pg_temp'
    AS $$
DECLARE
  v_affected INTEGER;
BEGIN
  DELETE FROM public.appointments
  WHERE appointment_date < NOW() - INTERVAL '2 years';

  GET DIAGNOSTICS v_affected = ROW_COUNT;
  RETURN v_affected;
END;
$$;


ALTER FUNCTION "public"."delete_old_appointments"() OWNER TO "postgres";


COMMENT ON FUNCTION "public"."delete_old_appointments"() IS 'Deleta agendamentos com mais de 2 anos (obrigação contábil)';



CREATE OR REPLACE FUNCTION "public"."ensure_whatsapp_confirmation"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_token TEXT;
BEGIN
  -- Executar de forma assíncrona (não bloquear o INSERT do appointment)
  PERFORM pg_notify(
    'check_whatsapp_confirmation',
    json_build_object(
      'appointment_id', NEW.id,
      'check_at', NOW() + INTERVAL '120 seconds'
    )::text
  );
  
  -- Agendar verificação para 120 segundos depois
  -- Usar pg_cron ou criar registro que será processado por worker
  INSERT INTO whatsapp_retry_queue (
    appointment_id,
    message_type,
    phone_number,
    template_data,
    status,
    retry_count,
    next_retry_at,
    error_message
  )
  SELECT 
    NEW.id,
    'confirmation',
    c.phone,
    json_build_object(
      'customerName', c.name,
      'customerPhone', c.phone,
      'barberName', b.name,
      'serviceName', s.name,
      'barbershopName', bb.name,
      'barbershopAddress', bb.address,
      'appointmentDate', NEW.appointment_date,
      'appointmentTime', to_char(NEW.appointment_time, 'HH24:MI'),
      'managementUrl', CASE 
        WHEN t.token IS NOT NULL 
        THEN 'https://navalha-hub.lovable.app/gerenciar/' || t.token
        ELSE NULL
      END
    ),
    'pending',
    0,
    NOW() + INTERVAL '120 seconds',
    'Fallback automático: WhatsApp não enviado pelo frontend'
  FROM customers c
  INNER JOIN barbers b ON b.id = NEW.barber_id
  INNER JOIN services s ON s.id = NEW.service_id
  INNER JOIN barbershops bb ON bb.id = NEW.barbershop_id
  LEFT JOIN appointment_tokens t ON t.appointment_id = NEW.id
  WHERE c.id = NEW.customer_id
    -- Só adicionar se ainda não existir na fila
    AND NOT EXISTS (
      SELECT 1 FROM whatsapp_retry_queue wrq
      WHERE wrq.appointment_id = NEW.id
      AND wrq.message_type = 'confirmation'
    )
    -- E se não foi enviado ainda
    AND NOT EXISTS (
      SELECT 1 FROM whatsapp_logs wl
      WHERE wl.appointment_id = NEW.id
      AND wl.message_type = 'confirmation'
      AND wl.status = 'sent'
    );
  
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."ensure_whatsapp_confirmation"() OWNER TO "postgres";


COMMENT ON FUNCTION "public"."ensure_whatsapp_confirmation"() IS 'Trigger de fallback que garante que todo appointment confirmado recebe uma confirmação WhatsApp. 
Adiciona automaticamente à retry queue 120 segundos após criação se WhatsApp não foi enviado.';



CREATE OR REPLACE FUNCTION "public"."execute_lgpd_retention_anonymization"() RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
  v_customers_affected INTEGER := 0;
BEGIN
  -- We target customers who have NO appointments in the last 5 years (1825 days)
  -- Or who were created > 5 years ago and NEVER had an appointment.
  -- Batch Limit to 5000 to prevent Table Excluvise Locks from blocking the UX.
  
  WITH InactiveTargetBatch AS (
      SELECT c.id 
      FROM public.customers c
      LEFT JOIN public.appointments a ON c.id = a.customer_id
      GROUP BY c.id
      HAVING 
         -- Condition 1: Has appointments, but the last one was over 5 years ago
         (MAX(a.appointment_date) < CURRENT_DATE - INTERVAL '5 years')
         OR 
         -- Condition 2: Never had an appointment, and account creation is over 5 years ago
         (MAX(a.appointment_date) IS NULL AND MAX(c.created_at) < NOW() - INTERVAL '5 years')
      LIMIT 5000
      FOR NO KEY UPDATE OF c -- Minimize locking strictly to target rows
  )
  UPDATE public.customers c
  SET 
    name = 'Anonimizado LGPD',
    phone = '00000000000',
    -- Crucial: To bypass any UNIQUE DB constraints, we inject the UUID inside the anon string
    email = CONCAT('anon_', c.id::text, '@anon.navalhahub.com'),
    updated_at = NOW()
  FROM InactiveTargetBatch tb
  WHERE c.id = tb.id
    -- Don't re-anonymize already anonymized data
    AND c.email NOT LIKE 'anon_%@anon.navalhahub.com';

  GET DIAGNOSTICS v_customers_affected = ROW_COUNT;

  -- 3. Log the Execution if any rows were affected
  IF v_customers_affected > 0 THEN
      INSERT INTO public.data_retention_audit_log (operation_type, records_anonymized)
      VALUES ('BATCH_LGPD_ANONYMIZATION', v_customers_affected);
      
      RAISE NOTICE 'Execução LGPD Completa: % clientes formatados irreversivelmente.', v_customers_affected;
  END IF;

END;
$$;


ALTER FUNCTION "public"."execute_lgpd_retention_anonymization"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."freeze_completed_financials"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
begin
  if (auth.role() = 'service_role') then return new; end if;
  if (old.status = 'completed') or (new.status = 'completed') then
      if (new.price is distinct from old.price) or (new.final_amount is distinct from old.final_amount) then
          raise exception 'SECURITY ALERT: Cannot modify financials of a completed appointment.';
      end if;
  end if;
  return new;
end;
$$;


ALTER FUNCTION "public"."freeze_completed_financials"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."generate_appointment_token"("p_appointment_id" "uuid") RETURNS "text"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public', 'extensions'
    AS $$
DECLARE
  v_token TEXT;
  v_expires_at TIMESTAMP;
BEGIN
  
  -- Generate 64-char hex token (standard)
  v_token := encode(gen_random_bytes(32), 'hex');
  v_expires_at := NOW() + INTERVAL '48 hours';
  
  -- Professional UPSERT
  INSERT INTO public.appointment_tokens (
    appointment_id, 
    token, 
    expires_at, 
    created_at
  ) VALUES (
    p_appointment_id, 
    v_token, 
    v_expires_at, 
    NOW()
  )
  ON CONFLICT ON CONSTRAINT uk_appointment_tokens_appointment_id
  DO UPDATE SET
    token = EXCLUDED.token,
    expires_at = EXCLUDED.expires_at,
    created_at = NOW();
    
  RETURN v_token;
  
END;
$$;


ALTER FUNCTION "public"."generate_appointment_token"("p_appointment_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."generate_backup_codes_secure"() RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'pg_catalog', 'public', 'extensions', 'pg_temp'
    AS $$
DECLARE
  v_user_id UUID;
  v_aal     TEXT;
  v_codes   TEXT[] := ARRAY[]::TEXT[];
  v_code    TEXT;
  v_hash    TEXT;
  i         INT;
BEGIN
  v_user_id := auth.uid();
  IF v_user_id IS NULL THEN
    RAISE EXCEPTION 'Not authenticated' USING ERRCODE = 'P0401';
  END IF;

  -- ⚡ CRÍTICO: Verificar que sessão é AAL2 (MFA já verificado)
  -- auth.jwt()->>'aal' lê o claim do JWT atual sem round-trip
  v_aal := auth.jwt()->>'aal';
  IF v_aal IS DISTINCT FROM 'aal2' THEN
    RAISE EXCEPTION 'MFA verification required (AAL2) to generate backup codes'
      USING ERRCODE = 'P0403',
            HINT    = 'Complete MFA challenge before generating recovery codes.';
  END IF;

  -- Invalidar códigos anteriores (rotação obrigatória)
  UPDATE public.backup_codes
  SET used_at = NOW()
  WHERE user_id = v_user_id AND used_at IS NULL;

  -- Gerar 10 novos códigos únicos (formato XXXX-XXXX)
  FOR i IN 1..10 LOOP
    v_code := upper(
      substring(encode(gen_random_bytes(4), 'hex') FROM 1 FOR 4) || '-' ||
      substring(encode(gen_random_bytes(4), 'hex') FROM 1 FOR 4)
    );
    v_codes := array_append(v_codes, v_code);

    -- Hash bcrypt via pgcrypto
    v_hash := crypt(v_code, gen_salt('bf', 10));

    INSERT INTO public.backup_codes (user_id, code_hash, expires_at)
    VALUES (v_user_id, v_hash, NOW() + INTERVAL '1 year');
  END LOOP;

  -- Retornar apenas uma vez os códigos em texto (não são armazenados em plain text)
  -- O frontend deve mostrar e pedir confirmação de salvamento
  RETURN jsonb_build_object(
    'codes', to_jsonb(v_codes),
    'generated_at', NOW(),
    'expires_at', NOW() + INTERVAL '1 year',
    'warning', 'Store these codes securely. They will not be shown again.'
  );
END;
$$;


ALTER FUNCTION "public"."generate_backup_codes_secure"() OWNER TO "postgres";


COMMENT ON FUNCTION "public"."generate_backup_codes_secure"() IS '[SOVEREIGN V4.12] Backup code generator. REQUIRES AAL2 (active MFA session). Rotates all existing codes on each call.';



CREATE OR REPLACE FUNCTION "public"."get_appointment_by_token"("token_input" "text") RETURNS json
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
DECLARE
  result JSON;
BEGIN
  
  -- Fetch appointment data with all necessary relations
  -- RLS will now be enforced on all joined tables
  SELECT json_build_object(
    'id', a.id,
    'appointment_date', a.appointment_date,
    'appointment_time', a.appointment_time,
    'status', a.status,
    'barbershop', json_build_object(
      'name', b.name,
      'slug', b.slug,
      'address', b.address
    ),
    'barber', json_build_object(
      'name', br.name,
      'id', br.id
    ),
    'service', json_build_object(
      'name', s.name,
      'duration_minutes', s.duration_minutes,
      'id', s.id
    ),
    'customer', json_build_object(
      'name', c.name,
      'phone', c.phone
    )
  ) INTO result
  FROM appointment_tokens at
  INNER JOIN appointments a ON at.appointment_id = a.id
  INNER JOIN barbershops b ON a.barbershop_id = b.id
  INNER JOIN barbers br ON a.barber_id = br.id
  INNER JOIN services s ON a.service_id = s.id
  INNER JOIN customers c ON a.customer_id = c.id
  WHERE at.token = token_input
    AND at.expires_at > NOW()
    AND at.used_at IS NULL;

  -- If not found, return error
  IF result IS NULL THEN
    RAISE EXCEPTION 'TOKEN_NOT_FOUND';
  END IF;

  RETURN result;
  
END;
$$;


ALTER FUNCTION "public"."get_appointment_by_token"("token_input" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_appointment_details_for_whatsapp"("p_appointment_id" "uuid") RETURNS json
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_result JSON;
BEGIN
  
  -- Fetch appointment details with all relations
  -- RLS will now be enforced on all joined tables
  SELECT json_build_object(
    'id', a.id,
    'barbershop_id', a.barbershop_id,
    'appointment_date', a.appointment_date,
    'appointment_time', a.appointment_time,
    'customer_name', c.name,
    'customer_phone', c.phone,
    'barber_name', b.name,
    'service_name', s.name,
    'barbershop_name', bb.name,
    'barbershop_address', bb.address
  ) INTO v_result
  FROM appointments a
  INNER JOIN customers c ON a.customer_id = c.id
  INNER JOIN barbers b ON a.barber_id = b.id
  INNER JOIN services s ON a.service_id = s.id
  INNER JOIN barbershops bb ON a.barbershop_id = bb.id
  WHERE a.id = p_appointment_id;
  
  IF v_result IS NULL THEN
    RAISE EXCEPTION 'Agendamento não encontrado: %', p_appointment_id;
  END IF;
  
  RETURN v_result;
  
END;
$$;


ALTER FUNCTION "public"."get_appointment_details_for_whatsapp"("p_appointment_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_appointments_for_1h_reminder"() RETURNS TABLE("id" "uuid", "appointment_date" "date", "appointment_time" time without time zone, "customer_phone" "text", "customer_name" "text", "barber_name" "text", "service_name" "text", "barbershop_name" "text", "barbershop_id" "uuid", "barbershop_address" "text")
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_now timestamp;
  v_target_start timestamp;
  v_target_end timestamp;
BEGIN
  v_now := CURRENT_TIMESTAMP AT TIME ZONE 'America/Sao_Paulo';
  v_target_start := v_now + INTERVAL '55 minutes';
  v_target_end   := v_now + INTERVAL '65 minutes';

  RETURN QUERY
  WITH candidates AS (
      SELECT a.id
      FROM public.appointments a
      JOIN public.barbershops bs ON a.barbershop_id = bs.id
      WHERE 
        a.status = 'confirmed'
        AND a.reminder_1h_sent = false
        AND bs.deleted_at IS NULL
        AND bs.subscription_status != 'cancelled'
        AND (
           (a.appointment_date || ' ' || a.appointment_time)::timestamp 
           AT TIME ZONE 'America/Sao_Paulo'
        ) BETWEEN v_target_start AND v_target_end
      LIMIT 50
      FOR UPDATE SKIP LOCKED -- 🔒 ATOMIC LOCK
  ),
  marked AS (
      UPDATE public.appointments
      SET reminder_1h_sent = true, -- 🚩 ATOMIC CLAIM
          updated_at = now()
      WHERE id IN (SELECT id FROM candidates)
      RETURNING id
  )
  SELECT 
    a.id,
    a.appointment_date,
    a.appointment_time,
    c.phone as customer_phone,
    c.name as customer_name,
    b.name as barber_name,
    s.name as service_name,
    bs.name as barbershop_name,
    bs.id as barbershop_id,
    bs.address as barbershop_address
  FROM public.appointments a
  JOIN public.customers c ON a.customer_id = c.id
  JOIN public.barbers b ON a.barber_id = b.id
  JOIN public.services s ON a.service_id = s.id
  JOIN public.barbershops bs ON a.barbershop_id = bs.id
  WHERE a.id IN (SELECT id FROM marked);
END;
$$;


ALTER FUNCTION "public"."get_appointments_for_1h_reminder"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_appointments_for_24h_reminder"() RETURNS TABLE("id" "uuid", "appointment_date" "date", "appointment_time" time without time zone, "customer_phone" "text", "customer_name" "text", "barber_name" "text", "service_name" "text", "barbershop_name" "text", "barbershop_id" "uuid", "barbershop_address" "text")
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
BEGIN
  RETURN QUERY
  WITH candidates AS (
      SELECT a.id
      FROM public.appointments a
      JOIN public.barbershops bs ON a.barbershop_id = bs.id
      WHERE 
        a.status = 'confirmed'
        AND a.reminder_24h_sent = false
        AND bs.deleted_at IS NULL
        AND bs.subscription_status != 'cancelled'
        AND a.appointment_date = ((CURRENT_TIMESTAMP AT TIME ZONE 'America/Sao_Paulo')::date + INTERVAL '1 day')
      LIMIT 50
      FOR UPDATE SKIP LOCKED -- 🔒 ATOMIC LOCK: Prevent other crons from picking these
  ),
  marked AS (
      UPDATE public.appointments
      SET reminder_24h_sent = true, -- 🚩 ATOMIC CLAIM: Mark as sent BEFORE sending
          updated_at = now()
      WHERE id IN (SELECT id FROM candidates)
      RETURNING id
  )
  SELECT 
    a.id,
    a.appointment_date,
    a.appointment_time,
    c.phone as customer_phone,
    c.name as customer_name,
    b.name as barber_name,
    s.name as service_name,
    bs.name as barbershop_name,
    bs.id as barbershop_id,
    bs.address as barbershop_address
  FROM public.appointments a
  JOIN public.customers c ON a.customer_id = c.id
  JOIN public.barbers b ON a.barber_id = b.id
  JOIN public.services s ON a.service_id = s.id
  JOIN public.barbershops bs ON a.barbershop_id = bs.id
  WHERE a.id IN (SELECT id FROM marked);
END;
$$;


ALTER FUNCTION "public"."get_appointments_for_24h_reminder"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_available_slots"("p_barber_id" "uuid", "p_date" "date", "p_duration_minutes" integer, "p_start_time" time without time zone DEFAULT '09:00:00'::time without time zone, "p_end_time" time without time zone DEFAULT '18:00:00'::time without time zone, "p_interval_minutes" integer DEFAULT 30) RETURNS "text"[]
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
  RETURN ARRAY(
    SELECT to_char(slot_start, 'HH24:MI')
    FROM generate_series(
      (p_date || ' ' || p_start_time)::timestamp,
      (p_date || ' ' || p_end_time)::timestamp - (p_duration_minutes || ' minutes')::interval,
      (p_interval_minutes || ' minutes')::interval
    ) AS slot_start
    WHERE NOT EXISTS (
      SELECT 1 FROM appointments a
      WHERE a.barber_id = p_barber_id
        AND a.appointment_date = p_date
        AND a.status IN ('confirmed', 'pending')
        AND (
            (slot_start::time >= a.appointment_time AND slot_start::time < (a.appointment_time + (p_duration_minutes || ' minutes')::interval))
            OR
            ((slot_start::time + (p_duration_minutes || ' minutes')::interval) > a.appointment_time AND (slot_start::time + (p_duration_minutes || ' minutes')::interval) <= (a.appointment_time + (p_duration_minutes || ' minutes')::interval))
            OR
            (slot_start::time <= a.appointment_time AND (slot_start::time + (p_duration_minutes || ' minutes')::interval) >= (a.appointment_time + (p_duration_minutes || ' minutes')::interval))
        )
    )
  );
END;
$$;


ALTER FUNCTION "public"."get_available_slots"("p_barber_id" "uuid", "p_date" "date", "p_duration_minutes" integer, "p_start_time" time without time zone, "p_end_time" time without time zone, "p_interval_minutes" integer) OWNER TO "postgres";


COMMENT ON FUNCTION "public"."get_available_slots"("p_barber_id" "uuid", "p_date" "date", "p_duration_minutes" integer, "p_start_time" time without time zone, "p_end_time" time without time zone, "p_interval_minutes" integer) IS 'Retorna array de horários disponíveis para um barbeiro em uma data específica. Otimiza queries do frontend eliminando múltiplas chamadas RPC.';



CREATE OR REPLACE FUNCTION "public"."get_available_times"("p_barbershop_slug" "text", "p_barber_id" "uuid", "p_date" "date") RETURNS json[]
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_barbershop_id uuid;
  v_available_times json[];
  v_time time;
  v_is_available boolean;
BEGIN
  -- Buscar barbearia
  SELECT id INTO v_barbershop_id
  FROM public.barbershops
  WHERE slug = p_barbershop_slug;
  
  IF v_barbershop_id IS NULL THEN
    RAISE EXCEPTION 'Barbearia não encontrada';
  END IF;

  -- Gerar horários das 9:00 às 18:00
  v_available_times := ARRAY[]::json[];
  
  FOR v_time IN 
    SELECT generate_series(
      '09:00'::time,
      '18:00'::time,
      '30 minutes'::interval
    )::time
    WHERE generate_series < '18:30'::time
  LOOP
    -- Verificar se horário está disponível
    SELECT COUNT(*) = 0 INTO v_is_available
    FROM public.appointments
    WHERE barbershop_id = v_barbershop_id
      AND barber_id = p_barber_id
      AND appointment_date = p_date
      AND appointment_time = v_time
      AND status NOT IN ('cancelled', 'completed');
    
    IF v_is_available THEN
      v_available_times := array_append(
        v_available_times,
        json_build_object('time', v_time, 'available', true)
      );
    END IF;
  END LOOP;

  RETURN v_available_times;
END;
$$;


ALTER FUNCTION "public"."get_available_times"("p_barbershop_slug" "text", "p_barber_id" "uuid", "p_date" "date") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_barber_monthly_report"("p_barbershop_id" "uuid", "p_barber_id" "uuid", "p_start_date" "date", "p_end_date" "date") RETURNS TABLE("month" "text", "total_earnings" numeric, "transaction_count" bigint)
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'rpc'
    AS $$
BEGIN
    -- [SECURITY DEFINER] IDOR PROTECTION: Verify caller is the barber OR the owner
    IF NOT (
        -- Is the barber themselves
        (p_barber_id IN (SELECT id FROM public.barbers WHERE user_id = auth.uid()))
        OR
        -- Is the owner of the shop
        EXISTS (SELECT 1 FROM public.barbershops WHERE id = p_barbershop_id AND owner_id = auth.uid())
    ) THEN
        RAISE EXCEPTION 'Access Denied: You do not have permission to view this report' USING ERRCODE = 'P0001';
    END IF;

    RETURN QUERY
    SELECT
        TO_CHAR(created_at, 'YYYY-MM') as month_key,
        COALESCE(SUM(amount), 0) as total_earnings,
        COUNT(*) as tx_count
    FROM financial_ledger
    WHERE barbershop_id = p_barbershop_id
      AND barber_id = p_barber_id
      AND transaction_type = 'commission_credit'
      AND created_at >= p_start_date
      AND created_at <= p_end_date
    GROUP BY 1
    ORDER BY 1 DESC;
END;
$$;


ALTER FUNCTION "public"."get_barber_monthly_report"("p_barbershop_id" "uuid", "p_barber_id" "uuid", "p_start_date" "date", "p_end_date" "date") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_barber_performance_metrics"("p_barbershop_id" "uuid", "p_start_date" timestamp with time zone, "p_end_date" timestamp with time zone) RETURNS TABLE("barber_name" "text", "avatar_url" "text", "total_appointments" bigint, "total_revenue" numeric, "avg_ticket" numeric, "retention_count" bigint, "retention_rate" numeric, "cancellation_count" bigint, "cancellation_rate" numeric)
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
BEGIN
    RETURN QUERY
    WITH BarberStats AS (
        SELECT
            b.id AS barber_id,
            b.name,
            b.avatar_url,  -- Fixed ambiguity here if needed, but mainly ensured b table is clear
            
            -- Totals based on Status
            COUNT(CASE WHEN a.status = 'completed' THEN 1 END) AS appt_count,
            COUNT(CASE WHEN a.status = 'cancelled' THEN 1 END) AS cancel_count,
            
            -- Revenue only from completed
            COALESCE(SUM(CASE WHEN a.status = 'completed' THEN COALESCE(a.final_amount, a.total_amount, 0) ELSE 0 END), 0) AS revenue,
            
            -- Retention (Based on Completed)
            COUNT(
                CASE WHEN a.status = 'completed' AND EXISTS (
                    SELECT 1 
                    FROM appointments history 
                    WHERE history.customer_id = a.customer_id 
                      AND history.status = 'completed'
                      AND history.appointment_date < a.appointment_date
                ) THEN 1 END
            ) AS recurring_clients
        FROM
            barbers b
        LEFT JOIN
            appointments a ON b.id = a.barber_id
        WHERE
            b.barbershop_id = p_barbershop_id
            AND a.appointment_date >= p_start_date
            AND a.appointment_date <= p_end_date
        GROUP BY
            b.id
    )
    SELECT
        name::text,
        -- Fixed: Explicit cast to text for return type match
        avatar_url::text,
        appt_count,
        revenue,
        CASE 
            WHEN appt_count > 0 THEN ROUND(revenue / appt_count, 2)
            ELSE 0 
        END AS avg_ticket,
        recurring_clients AS retention_count,
        CASE 
            WHEN appt_count > 0 THEN ROUND((recurring_clients::numeric / appt_count::numeric) * 100, 2)
            ELSE 0 
        END AS retention_rate,
        cancel_count,
        CASE 
            WHEN (appt_count + cancel_count) > 0 THEN ROUND((cancel_count::numeric / (appt_count + cancel_count)::numeric) * 100, 2)
            ELSE 0
        END AS cancellation_rate
    FROM
        BarberStats
    ORDER BY
        revenue DESC;
END;
$$;


ALTER FUNCTION "public"."get_barber_performance_metrics"("p_barbershop_id" "uuid", "p_start_date" timestamp with time zone, "p_end_date" timestamp with time zone) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_barbershop_settings"("barbershop_id" "uuid") RETURNS TABLE("megaapi_token" "text", "megaapi_instance_key" "text", "stripe_customer_id" "text", "stripe_subscription_id" "text")
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
  -- Verify if the caller is the owner of the barbershop
  IF NOT EXISTS (
    SELECT 1 FROM barbershops 
    WHERE id = barbershop_id 
    AND owner_id = auth.uid()
  ) THEN
    RAISE EXCEPTION 'Access Denied';
  END IF;

  RETURN QUERY
  SELECT 
    b.megaapi_token,
    b.megaapi_instance_key,
    b.stripe_customer_id,
    b.stripe_subscription_id
  FROM barbershops b
  WHERE b.id = barbershop_id;
END;
$$;


ALTER FUNCTION "public"."get_barbershop_settings"("barbershop_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_daily_metrics"("p_barbershop_id" "uuid", "p_start_date" timestamp with time zone, "p_end_date" timestamp with time zone) RETURNS TABLE("date" "date", "daily_revenue" numeric, "daily_appointments" bigint)
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
BEGIN
    RETURN QUERY
    SELECT
        DATE(appointment_date) as day,
        COALESCE(SUM(COALESCE(final_amount, total_amount, 0)), 0) as revenue,
        COUNT(id) as appts
    FROM
        appointments
    WHERE
        barbershop_id = p_barbershop_id
        AND status = 'completed'
        AND appointment_date >= p_start_date
        AND appointment_date <= p_end_date
    GROUP BY
        DATE(appointment_date)
    ORDER BY
        day ASC;
END;
$$;


ALTER FUNCTION "public"."get_daily_metrics"("p_barbershop_id" "uuid", "p_start_date" timestamp with time zone, "p_end_date" timestamp with time zone) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_dashboard_kpis"("p_barbershop_id" "uuid", "p_start_date" timestamp with time zone, "p_end_date" timestamp with time zone) RETURNS TABLE("total_revenue" numeric, "total_appointments" bigint, "unique_customers" bigint, "avg_ticket" numeric, "avg_rev_per_customer" numeric, "growth_vs_previous" numeric)
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'extensions', 'pg_temp'
    AS $$
DECLARE
    v_previous_start timestamp with time zone;
    v_previous_end timestamp with time zone;
    v_interval interval;
BEGIN
    -- [SECURITY DEFINER] SOVEREIGN IDOR PROTECTION: Verify caller is owner
    IF NOT EXISTS (
        SELECT 1 FROM public.barbershops 
        WHERE id = p_barbershop_id AND owner_id = auth.uid()
    ) THEN
        RAISE EXCEPTION 'Sovereign Security Block: Access Denied. You do not own this barbershop.' USING ERRCODE = 'P0001';
    END IF;

    v_interval := p_end_date - p_start_date;
    v_previous_end := p_start_date;
    v_previous_start := p_start_date - v_interval;

    RETURN QUERY
    WITH stats AS (
        SELECT
            COALESCE(SUM(CASE WHEN appointment_date >= p_start_date AND appointment_date <= p_end_date THEN COALESCE(final_amount, total_amount, 0) ELSE 0 END), 0) as curr_rev,
            COUNT(CASE WHEN appointment_date >= p_start_date AND appointment_date <= p_end_date THEN 1 END) as curr_count,
            COUNT(DISTINCT CASE WHEN appointment_date >= p_start_date AND appointment_date <= p_end_date THEN customer_id END) as curr_unique,
            COALESCE(SUM(CASE WHEN appointment_date >= v_previous_start AND appointment_date < v_previous_end THEN COALESCE(final_amount, total_amount, 0) ELSE 0 END), 0) as prev_rev
        FROM appointments
        WHERE barbershop_id = p_barbershop_id
          AND status = 'completed'
          AND appointment_date >= v_previous_start 
          AND appointment_date <= p_end_date       
    )
    SELECT
        curr_rev,
        curr_count,
        curr_unique,
        CASE WHEN curr_count > 0 THEN ROUND(curr_rev / curr_count, 2) ELSE 0 END,
        CASE WHEN curr_unique > 0 THEN ROUND(curr_rev / curr_unique, 2) ELSE 0 END,
        CASE
            WHEN prev_rev > 0 THEN ROUND(((curr_rev - prev_rev) / prev_rev) * 100, 2)
            WHEN curr_rev > 0 THEN 100
            ELSE 0
        END
    FROM stats;
END;
$$;


ALTER FUNCTION "public"."get_dashboard_kpis"("p_barbershop_id" "uuid", "p_start_date" timestamp with time zone, "p_end_date" timestamp with time zone) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_dashboard_stats"("p_barbershop_id" "uuid") RETURNS json
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_today DATE;
  v_first_day DATE;
  v_result JSON;
  v_appointments_today INTEGER;
  v_monthly_revenue NUMERIC;
BEGIN
  -- [SECURITY DEFINER] SOVEREIGN IDOR PROTECTION: Verify caller is owner
  IF NOT EXISTS (
      SELECT 1 FROM public.barbershops 
      WHERE id = p_barbershop_id AND owner_id = auth.uid()
  ) THEN
      RAISE EXCEPTION 'Sovereign Security Block: Access Denied. You do not own this barbershop.' USING ERRCODE = 'P0001';
  END IF;

  v_today := (now() AT TIME ZONE 'America/Sao_Paulo')::DATE;
  v_first_day := date_trunc('month', v_today)::DATE;

  SELECT COALESCE(appointments_count, 0) INTO v_appointments_today
  FROM public.daily_metrics
  WHERE barbershop_id = p_barbershop_id AND date = v_today;

  SELECT COALESCE(SUM(revenue), 0) INTO v_monthly_revenue
  FROM public.daily_metrics
  WHERE barbershop_id = p_barbershop_id AND date >= v_first_day;
  
  SELECT json_build_object(
    'appointmentsToday', COALESCE(v_appointments_today, 0),
    'activeBarbers', (SELECT COUNT(*) FROM public.barbers WHERE barbershop_id = p_barbershop_id AND is_active = true),
    'totalCustomers', (SELECT COUNT(*) FROM public.customers WHERE barbershop_id = p_barbershop_id),
    'monthlyRevenue', COALESCE(v_monthly_revenue, 0)
  ) INTO v_result;

  RETURN v_result;
END;
$$;


ALTER FUNCTION "public"."get_dashboard_stats"("p_barbershop_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_dashboard_stats_v2"("p_barbershop_id" "uuid", "p_month" "date" DEFAULT CURRENT_DATE) RETURNS TABLE("appointments_today" bigint, "monthly_revenue" numeric)
    LANGUAGE "sql" STABLE
    AS $$
  WITH metrics AS (
     SELECT * FROM public.view_daily_metrics_unified
     WHERE barbershop_id = p_barbershop_id
  )
  SELECT
     COALESCE((SELECT total_appointments FROM metrics WHERE date = p_month), 0),
     COALESCE((SELECT SUM(total_revenue) FROM metrics WHERE date >= date_trunc('month', p_month) AND date < date_trunc('month', p_month) + interval '1 month'), 0);
$$;


ALTER FUNCTION "public"."get_dashboard_stats_v2"("p_barbershop_id" "uuid", "p_month" "date") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_day_availability"("p_barber_id" "uuid", "p_date" "date", "p_service_id" "uuid") RETURNS TABLE("slot" time without time zone, "available" boolean)
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
    v_duration INTEGER;
    v_padding INTEGER;
    v_start_hour TIME;
    v_end_hour TIME;
BEGIN
    SELECT 
        COALESCE(s.duration_minutes, 30), 
        COALESCE(s.padding_minutes, 0),
        COALESCE(b.opening_time, '09:00'::TIME),
        COALESCE(b.closing_time, '18:00'::TIME)
    INTO v_duration, v_padding, v_start_hour, v_end_hour
    FROM services s
    JOIN barbershops b ON b.id = s.barbershop_id
    WHERE s.id = p_service_id;
    
    IF v_duration IS NULL THEN v_duration := 30; END IF;
    IF v_padding IS NULL THEN v_padding := 0; END IF;
    IF v_start_hour IS NULL THEN v_start_hour := '09:00:00'::TIME; END IF;
    IF v_end_hour IS NULL THEN v_end_hour := '18:00:00'::TIME; END IF;

    RETURN QUERY
    WITH generated_slots AS (
        SELECT generate_series(
            p_date + v_start_hour, 
            p_date + v_end_hour - interval '1 minute', 
            '30 minutes'::interval
        )::TIME as virtual_slot
    ),
    daily_appointments AS (
        SELECT 
            a.appointment_time, 
            COALESCE(
               a.appointment_end_time, 
               a.appointment_time + (COALESCE(s.duration_minutes, 60) || ' minutes')::interval
            ) as appointment_end_time,
            COALESCE(s.padding_minutes, 0) as padding_minutes
        FROM appointments a
        LEFT JOIN services s ON a.service_id = s.id
        WHERE a.barber_id = p_barber_id
          AND a.appointment_date = p_date
          AND a.status IN ('confirmed', 'pending')
    )
    SELECT 
        gs.virtual_slot,
        NOT EXISTS (
            SELECT 1 
            FROM daily_appointments da
            WHERE 
                gs.virtual_slot < (da.appointment_end_time + (da.padding_minutes || ' minutes')::interval)
                AND
                (gs.virtual_slot + ((v_duration + v_padding) || ' minutes')::interval) > da.appointment_time
        ) AS available
    FROM generated_slots gs;
END;
$$;


ALTER FUNCTION "public"."get_day_availability"("p_barber_id" "uuid", "p_date" "date", "p_service_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_day_availability"("p_barbershop_id" "uuid", "p_barber_id" "uuid", "p_date" "date") RETURNS TABLE("time_slot" "text", "is_available" boolean)
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_start_hour TIME;
  v_end_hour   TIME;
  v_slot_duration_minutes INT := 30;
BEGIN
  -- Ler horário de operação configurado pela barbearia (P-002 fix)
  SELECT opening_time, closing_time
  INTO   v_start_hour, v_end_hour
  FROM   public.barbershops
  WHERE  id = p_barbershop_id;

  -- Fallback seguro caso barbershop não encontrado
  IF NOT FOUND THEN
    v_start_hour := '09:00:00'::TIME;
    v_end_hour   := '18:00:00'::TIME;
  END IF;

  -- CTE: agendamentos existentes no dia/barbeiro
  RETURN QUERY
  WITH booked_slots AS (
    SELECT appointment_time AS slot
    FROM   public.appointments
    WHERE  barbershop_id     = p_barbershop_id
      AND  barber_id         = p_barber_id
      AND  appointment_date  = p_date
      AND  status NOT IN ('cancelled', 'no_show')
  ),
  all_slots AS (
    SELECT (v_start_hour + (n * (v_slot_duration_minutes || ' minutes')::INTERVAL))::TIME AS slot
    FROM   generate_series(
             0,
             EXTRACT(EPOCH FROM (v_end_hour - v_start_hour))::INT / (v_slot_duration_minutes * 60) - 1
           ) AS n
  )
  SELECT
    TO_CHAR(all_slots.slot, 'HH24:MI') AS time_slot,
    (booked_slots.slot IS NULL)         AS is_available
  FROM   all_slots
  LEFT JOIN booked_slots ON booked_slots.slot = all_slots.slot
  ORDER BY all_slots.slot;
END;
$$;


ALTER FUNCTION "public"."get_day_availability"("p_barbershop_id" "uuid", "p_barber_id" "uuid", "p_date" "date") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_financial_metrics"("p_barbershop_id" "uuid", "p_start_date" timestamp with time zone, "p_end_date" timestamp with time zone) RETURNS TABLE("total_revenue" numeric, "total_expenses" numeric, "total_commissions" numeric, "net_profit" numeric, "transaction_count" bigint)
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'rpc'
    AS $$
BEGIN
    -- [SECURITY DEFINER] IDOR PROTECTION: Verify caller is owner
    IF NOT EXISTS (
        SELECT 1 FROM public.barbershops 
        WHERE id = p_barbershop_id AND owner_id = auth.uid()
    ) THEN
        RAISE EXCEPTION 'Access Denied: You do not own this barbershop' USING ERRCODE = 'P0001';
    END IF;

    RETURN QUERY
    WITH metrics AS (
        SELECT
            COALESCE(SUM(CASE WHEN transaction_type = 'income' THEN amount ELSE 0 END), 0) as revenue,
            COALESCE(SUM(CASE WHEN transaction_type = 'expense' THEN amount ELSE 0 END), 0) as expenses,
            COALESCE(SUM(CASE WHEN transaction_type = 'commission_credit' THEN amount ELSE 0 END), 0) as commissions,
            COUNT(*) as tx_count
        FROM financial_ledger
        WHERE barbershop_id = p_barbershop_id
          AND created_at >= p_start_date
          AND created_at <= p_end_date
    ),
    manual_expenses AS (
        SELECT COALESCE(SUM(amount), 0) as manual_total
        FROM barbershop_expenses
        WHERE barbershop_id = p_barbershop_id
          AND date >= p_start_date::date
          AND date <= p_end_date::date
    )
    SELECT
        m.revenue,
        (m.expenses + me.manual_total),
        m.commissions,
        (m.revenue - (m.expenses + me.manual_total + m.commissions)),
        m.tx_count
    FROM metrics m
    CROSS JOIN manual_expenses me;
END;
$$;


ALTER FUNCTION "public"."get_financial_metrics"("p_barbershop_id" "uuid", "p_start_date" timestamp with time zone, "p_end_date" timestamp with time zone) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_monthly_financial_report"("p_barbershop_id" "uuid", "p_start_date" "date", "p_end_date" "date") RETURNS TABLE("month" "text", "total_revenue" numeric, "total_expenses" numeric, "total_commissions" numeric, "net_profit" numeric, "transaction_count" bigint)
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'rpc'
    AS $$
BEGIN
    -- [SECURITY DEFINER] IDOR PROTECTION: Verify caller is owner
    IF NOT EXISTS (
        SELECT 1 FROM public.barbershops 
        WHERE id = p_barbershop_id AND owner_id = auth.uid()
    ) THEN
        RAISE EXCEPTION 'Access Denied: You do not own this barbershop' USING ERRCODE = 'P0001';
    END IF;

    RETURN QUERY
    WITH monthly_ledger AS (
        SELECT
            TO_CHAR(created_at, 'YYYY-MM') as month_key,
            COALESCE(SUM(CASE WHEN transaction_type = 'income' THEN amount ELSE 0 END), 0) as revenue,
            COALESCE(SUM(CASE WHEN transaction_type = 'expense' THEN amount ELSE 0 END), 0) as expenses,
            COALESCE(SUM(CASE WHEN transaction_type = 'commission_credit' THEN amount ELSE 0 END), 0) as commissions,
            COUNT(*) as tx_count
        FROM financial_ledger
        WHERE barbershop_id = p_barbershop_id
          AND created_at >= p_start_date
          AND created_at <= p_end_date
        GROUP BY 1
    )
    SELECT
        ml.month_key, ml.revenue, ml.expenses, ml.commissions,
        (ml.revenue - (ml.expenses + ml.commissions)), ml.tx_count
    FROM monthly_ledger ml
    ORDER BY ml.month_key DESC;
END;
$$;


ALTER FUNCTION "public"."get_monthly_financial_report"("p_barbershop_id" "uuid", "p_start_date" "date", "p_end_date" "date") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_plan_barber_limit"("plan_name" "text") RETURNS integer
    LANGUAGE "sql" IMMUTABLE
    AS $$
  SELECT CASE 
    WHEN plan_name = 'premium' THEN 999
    WHEN plan_name = 'professional' THEN 10
    ELSE 3 -- Starter / Free / Trial / Null
  END;
$$;


ALTER FUNCTION "public"."get_plan_barber_limit"("plan_name" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_public_booking_data"("p_slug" "text") RETURNS json
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'extensions'
    AS $$
declare
    v_barbershop jsonb;
    v_barbers jsonb;
    v_services jsonb;
begin
    -- 1. Fetch Barbershop (Single Object)
    select to_jsonb(b) into v_barbershop
    from (
        select 
            id, name, slug, description, logo_url, 
            primary_color, secondary_color, 
            subscription_plan, subscription_status, trial_ends_at
        from public.barbershops
        where slug = p_slug
    ) b;

    -- Return null if not found (let frontend handle 404)
    if v_barbershop is null then
        return null;
    end if;

    -- 2. Fetch Barbers (Array)
    select coalesce(jsonb_agg(b), '[]'::jsonb) into v_barbers
    from (
        select id, name, avatar_url
        from public.barbers
        where barbershop_id = (v_barbershop->>'id')::uuid
        and is_active = true
    ) b;

    -- 3. Fetch Services (Array)
    select coalesce(jsonb_agg(s), '[]'::jsonb) into v_services
    from (
        select id, name, description, price, duration_minutes
        from public.services
        where barbershop_id = (v_barbershop->>'id')::uuid
        and is_active = true
    ) s;

    -- 4. Construct Result
    return json_build_object(
        'barbershop', v_barbershop,
        'barbers', v_barbers,
        'services', v_services
    );
end;
$$;


ALTER FUNCTION "public"."get_public_booking_data"("p_slug" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_server_time_iso"() RETURNS "text"
    LANGUAGE "sql" STABLE
    AS $$
  SELECT TO_CHAR(CURRENT_TIMESTAMP AT TIME ZONE 'America/Sao_Paulo', 'YYYY-MM-DD');
$$;


ALTER FUNCTION "public"."get_server_time_iso"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_top_services_metrics"("p_barbershop_id" "uuid", "p_start_date" timestamp with time zone, "p_end_date" timestamp with time zone) RETURNS TABLE("service_name" "text", "usage_count" bigint, "total_revenue" numeric, "percentage" numeric)
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
DECLARE
    v_total_revenue numeric;
BEGIN
    -- Calculate total revenue for the period (respecting RLS)
    SELECT COALESCE(SUM(COALESCE(final_amount, total_amount, 0)), 1)
    INTO v_total_revenue
    FROM appointments
    WHERE barbershop_id = p_barbershop_id
      AND status = 'completed'
      AND appointment_date >= p_start_date
      AND appointment_date <= p_end_date;

    RETURN QUERY
    SELECT
        s.name::text,
        COUNT(a.id) AS usage_count,
        COALESCE(SUM(COALESCE(a.final_amount, a.total_amount, 0)), 0) AS revenue,
        ROUND((COALESCE(SUM(COALESCE(a.final_amount, a.total_amount, 0)), 0) / NULLIF(v_total_revenue, 0)) * 100, 2) AS percentage
    FROM
        services s
    JOIN
        appointments a ON s.id = a.service_id
    WHERE
        s.barbershop_id = p_barbershop_id
        AND a.status = 'completed'
        AND a.appointment_date >= p_start_date
        AND a.appointment_date <= p_end_date
    GROUP BY
        s.id
    ORDER BY
        revenue DESC
    LIMIT 5;
END;
$$;


ALTER FUNCTION "public"."get_top_services_metrics"("p_barbershop_id" "uuid", "p_start_date" timestamp with time zone, "p_end_date" timestamp with time zone) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_user_id_by_phone"("p_phone" "text") RETURNS "text"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'auth'
    AS $$
DECLARE
  v_clean_phone text;
  v_user_id text;
BEGIN
  -- Normalize input: remove all non-digits
  v_clean_phone := regexp_replace(p_phone, '\D', '', 'g');

  -- 1. Search in AUTH.USERS (Truth Source)
  -- Matches if the stored phone (normalized) equals input (normalized)
  SELECT id INTO v_user_id
  FROM auth.users
  WHERE regexp_replace(phone, '\D', '', 'g') = v_clean_phone
  LIMIT 1;

  IF v_user_id IS NOT NULL THEN
    RETURN v_user_id;
  END IF;

  -- 2. Fallback: Search in PUBLIC.PROFILES
  SELECT id INTO v_user_id
  FROM public.profiles
  WHERE regexp_replace(phone, '\D', '', 'g') = v_clean_phone
  LIMIT 1;

  RETURN v_user_id;
END;
$$;


ALTER FUNCTION "public"."get_user_id_by_phone"("p_phone" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_user_identities"("p_user_id" "uuid") RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
    v_roles jsonb;
    v_owned_barbershops jsonb;
    v_working_barbershops jsonb;
    v_customer_profiles jsonb;
BEGIN
    -- 1. Get Global Roles
    SELECT jsonb_agg(role) INTO v_roles
    FROM public.user_roles
    WHERE user_id = p_user_id;

    -- 2. get OWNER Contexts
    SELECT jsonb_agg(jsonb_build_object('barbershopId', id, 'name', name, 'slug', slug, 'role', 'owner')) 
    INTO v_owned_barbershops
    FROM public.barbershops
    WHERE owner_id = p_user_id;

    -- 3. Get BARBER Contexts
    SELECT jsonb_agg(jsonb_build_object('barbershopId', barbershop_id, 'barberId', id, 'role', 'barber'))
    INTO v_working_barbershops
    FROM public.barbers
    WHERE user_id = p_user_id AND is_active = true;

    -- 4. Get CUSTOMER Contexts
    SELECT jsonb_agg(jsonb_build_object('barbershopId', barbershop_id, 'customerId', id, 'role', 'customer'))
    INTO v_customer_profiles
    FROM public.customers
    WHERE user_id = p_user_id;

    RETURN jsonb_build_object(
        'globalRoles', COALESCE(v_roles, '[]'::jsonb),
        'contexts', (
            COALESCE(v_owned_barbershops, '[]'::jsonb) || 
            COALESCE(v_working_barbershops, '[]'::jsonb) || 
            COALESCE(v_customer_profiles, '[]'::jsonb)
        )
    );
END;
$$;


ALTER FUNCTION "public"."get_user_identities"("p_user_id" "uuid") OWNER TO "postgres";


COMMENT ON FUNCTION "public"."get_user_identities"("p_user_id" "uuid") IS 'V3.4 Contextual Identity: Returns ALL contexts (Owner, Barber, Customer) for a user to support multi-tenancy switching.';



CREATE OR REPLACE FUNCTION "public"."get_user_identity"("p_user_id" "uuid") RETURNS json
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
    v_role text;
    v_barbershop_id uuid;
    v_barber_id uuid;
    v_customer_id uuid;
BEGIN
    SELECT raw_user_meta_data->>'role' INTO v_role
    FROM auth.users
    WHERE id = p_user_id;
    IF v_role = 'owner' THEN
        SELECT id INTO v_barbershop_id FROM public.barbershops WHERE owner_id = p_user_id LIMIT 1;
    ELSIF v_role = 'barber' THEN
        SELECT id, barbershop_id INTO v_barber_id, v_barbershop_id FROM public.barbers WHERE user_id = p_user_id LIMIT 1;
    ELSIF v_role = 'customer' THEN
        SELECT id INTO v_customer_id FROM public.customers WHERE user_id = p_user_id LIMIT 1;
    END IF;
    RETURN json_build_object(
        'role', v_role,
        'barbershopId', v_barbershop_id,
        'barberId', v_barber_id,
        'customerId', v_customer_id
    );
END;
$$;


ALTER FUNCTION "public"."get_user_identity"("p_user_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_user_setup_progress"("p_user_id" "uuid") RETURNS json
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_barbershop_id UUID;
  v_trial_ends_at TIMESTAMPTZ;
  v_has_barber BOOLEAN := FALSE;
  v_has_service BOOLEAN := FALSE;
  v_has_customer BOOLEAN := FALSE;
  v_has_appointment BOOLEAN := FALSE;
  v_has_completed_appointment BOOLEAN := FALSE;
  v_aha_moment_reached BOOLEAN := FALSE;
  v_progress_percentage INTEGER := 0;
  v_days_remaining INTEGER := 0;
  v_is_expired BOOLEAN := FALSE;
  v_completed_steps INTEGER := 0;
BEGIN
  -- Buscar barbershop do usuário
  SELECT id, trial_ends_at INTO v_barbershop_id, v_trial_ends_at
  FROM barbershops
  WHERE owner_id = p_user_id
  LIMIT 1;

  -- Se não tem barbershop, retorna estrutura vazia
  IF v_barbershop_id IS NULL THEN
    RETURN json_build_object(
      'has_barbershop', FALSE,
      'barbershop_id', NULL,
      'steps', NULL,
      'setup_complete', FALSE,
      'aha_moment_reached', FALSE,
      'progress_percentage', 0,
      'trial', json_build_object(
        'ends_at', NULL,
        'days_remaining', 0,
        'is_expired', FALSE
      )
    );
  END IF;

  -- Verificar cada step
  SELECT EXISTS(SELECT 1 FROM barbers WHERE barbershop_id = v_barbershop_id LIMIT 1) INTO v_has_barber;
  SELECT EXISTS(SELECT 1 FROM services WHERE barbershop_id = v_barbershop_id LIMIT 1) INTO v_has_service;
  SELECT EXISTS(SELECT 1 FROM customers WHERE barbershop_id = v_barbershop_id LIMIT 1) INTO v_has_customer;
  SELECT EXISTS(SELECT 1 FROM appointments WHERE barbershop_id = v_barbershop_id LIMIT 1) INTO v_has_appointment;
  SELECT EXISTS(SELECT 1 FROM appointments WHERE barbershop_id = v_barbershop_id AND status = 'completed' LIMIT 1) INTO v_has_completed_appointment;

  -- Aha moment = primeiro atendimento completado
  v_aha_moment_reached := v_has_completed_appointment;

  -- Calcular progresso (conta criada = 1 step já incluso = 20%)
  v_completed_steps := 1; -- Conta criada
  IF v_has_barber THEN v_completed_steps := v_completed_steps + 1; END IF;
  IF v_has_service THEN v_completed_steps := v_completed_steps + 1; END IF;
  IF v_has_customer THEN v_completed_steps := v_completed_steps + 1; END IF;
  IF v_has_appointment THEN v_completed_steps := v_completed_steps + 1; END IF;
  IF v_has_completed_appointment THEN v_completed_steps := v_completed_steps + 1; END IF;
  
  -- 6 passos totais (conta + 5 steps), cada um vale ~16.67%
  v_progress_percentage := LEAST(100, ROUND((v_completed_steps::NUMERIC / 6) * 100)::INTEGER);

  -- Calcular trial
  IF v_trial_ends_at IS NOT NULL THEN
    v_days_remaining := GREATEST(0, FLOOR(EXTRACT(EPOCH FROM v_trial_ends_at - NOW()) / 86400)::INTEGER);
    v_is_expired := v_trial_ends_at < NOW();
  END IF;

  RETURN json_build_object(
    'has_barbershop', TRUE,
    'barbershop_id', v_barbershop_id,
    'steps', json_build_object(
      'has_barber', v_has_barber,
      'has_service', v_has_service,
      'has_customer', v_has_customer,
      'has_appointment', v_has_appointment,
      'has_completed_appointment', v_has_completed_appointment
    ),
    'setup_complete', v_has_barber AND v_has_service AND v_has_customer AND v_has_appointment AND v_has_completed_appointment,
    'aha_moment_reached', v_aha_moment_reached,
    'progress_percentage', v_progress_percentage,
    'trial', json_build_object(
      'ends_at', v_trial_ends_at,
      'days_remaining', v_days_remaining,
      'is_expired', v_is_expired
    )
  );
END;
$$;


ALTER FUNCTION "public"."get_user_setup_progress"("p_user_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_whatsapp_stats"("p_barbershop_id" "uuid") RETURNS json
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_total_sent INTEGER;
  v_total_failed INTEGER;
  v_total_pending INTEGER;
  v_success_rate NUMERIC;
  v_last_24h_sent INTEGER;
  v_last_24h_failed INTEGER;
  v_retry_queue_pending INTEGER;
  v_retry_queue_failed INTEGER;
BEGIN
  -- 1. Count logs (History)
  SELECT 
    COUNT(*) FILTER (WHERE status = 'sent'),
    COUNT(*) FILTER (WHERE status = 'failed')
  INTO v_total_sent, v_total_failed
  FROM whatsapp_logs
  WHERE barbershop_id = p_barbershop_id;

  -- 2. Count logs last 24h
  SELECT 
    COUNT(*) FILTER (WHERE status = 'sent'),
    COUNT(*) FILTER (WHERE status = 'failed')
  INTO v_last_24h_sent, v_last_24h_failed
  FROM whatsapp_logs
  WHERE barbershop_id = p_barbershop_id
  AND sent_at > NOW() - INTERVAL '24 hours';

  -- 3. Calculate metrics
  IF (v_total_sent + v_total_failed) > 0 THEN
    v_success_rate := ROUND((v_total_sent::NUMERIC / (v_total_sent + v_total_failed)) * 100, 2);
  ELSE
    v_success_rate := 0;
  END IF;

  -- 4. Count Retry Queue (Pending/Failed)
  -- Note: We need to join with appointments to filter by barbershop_id
  SELECT 
    COUNT(*) FILTER (WHERE q.status = 'pending'),
    COUNT(*) FILTER (WHERE q.status = 'failed')
  INTO v_retry_queue_pending, v_retry_queue_failed
  FROM whatsapp_retry_queue q
  JOIN appointments a ON a.id = q.appointment_id
  WHERE a.barbershop_id = p_barbershop_id;

  -- 5. Return JSON
  RETURN json_build_object(
    'total_sent', COALESCE(v_total_sent, 0),
    'total_failed', COALESCE(v_total_failed, 0),
    'total_pending', 0, -- Deprecated/Not tracked in logs
    'success_rate', v_success_rate,
    'last_24h_sent', COALESCE(v_last_24h_sent, 0),
    'last_24h_failed', COALESCE(v_last_24h_failed, 0),
    'retry_queue_pending', COALESCE(v_retry_queue_pending, 0),
    'retry_queue_failed', COALESCE(v_retry_queue_failed, 0)
  );
END;
$$;


ALTER FUNCTION "public"."get_whatsapp_stats"("p_barbershop_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_whatsapp_status"("slug_input" "text") RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
  shop_id UUID;
  has_key BOOLEAN;
  is_owner BOOLEAN;
BEGIN
  -- Get ID and Key existence
  SELECT id, (megaapi_token IS NOT NULL) INTO shop_id, has_key
  FROM public.barbershops
  WHERE slug = slug_input;

  -- Check if requester is owner
  is_owner := (auth.uid() = (SELECT owner_id FROM public.barbershops WHERE id = shop_id));

  -- Return status only (never the key)
  RETURN jsonb_build_object(
    'connected', has_key,
    'is_owner', is_owner
  );
END;
$$;


ALTER FUNCTION "public"."get_whatsapp_status"("slug_input" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."guard_audit_logs_immutability"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
    IF current_setting('sovereign.allow_audit_janitor', true) = 'true' THEN
        RETURN OLD;
    END IF;

    RAISE EXCEPTION 'Sovereign Security Block: Audit Logs are mathematically immutable. UPDATE/DELETE operations are strictly forbidden.' 
    USING ERRCODE = 'P0001';
    
    RETURN NULL;
END;
$$;


ALTER FUNCTION "public"."guard_audit_logs_immutability"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."guard_barbershop_changes"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  -- 1. Verificar MFA para mudanÃ§as sensÃ­veis
  IF (TG_OP = 'UPDATE') THEN
    IF public.check_mfa_compliance() = false THEN
       RAISE EXCEPTION 'Acesso negado: AutenticaÃ§Ã£o de Dois Fatores (MFA) necessÃ¡ria para alterar configuraÃ§Ãµes.';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."guard_barbershop_changes"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."handle_appointment_completion"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
DECLARE
    v_commission_amount DECIMAL(10,2);
    v_existing_status TEXT;
BEGIN
    -- Se status mudou para 'completed'
    IF NEW.status = 'completed' AND (OLD.status IS DISTINCT FROM 'completed') THEN
        
        -- Calcular comissão (Preço * Taxa / 100)
        v_commission_amount := (NEW.price * NEW.commission_rate) / 100;

        -- Inserir ou Atualizar na tabela Commissions
        INSERT INTO public.commissions (
            barbershop_id,
            barber_id,
            appointment_id,
            amount,
            rate,
            reference_date,
            status
        ) VALUES (
            NEW.barbershop_id,
            NEW.barber_id,
            NEW.id,
            v_commission_amount,
            NEW.commission_rate,
            NEW.appointment_date,
            'pending'
        )
        ON CONFLICT (appointment_id) DO UPDATE SET
            amount = EXCLUDED.amount,
            rate = EXCLUDED.rate;
            
    -- Se status mudou de 'completed' para outra coisa (ex: cancelado por engano)
    ELSIF OLD.status = 'completed' AND NEW.status != 'completed' THEN
        
        -- SEGURANÇA FINANCEIRA: Verificar se já foi pago
        SELECT status INTO v_existing_status FROM public.commissions WHERE appointment_id = NEW.id;
        
        -- Se já foi pago, IMPEDIR alteração ou deletar
        IF v_existing_status = 'paid' THEN
             RAISE EXCEPTION 'SEGURANÇA FINANCEIRA: Não é possível cancelar/alterar um agendamento cuja comissão já foi PAGA ao barbeiro. Contate o administrador.';
        ELSE
             -- Se pendente, pode remover do extrato
             DELETE FROM public.commissions WHERE appointment_id = NEW.id;
        END IF;
    END IF;

    RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."handle_appointment_completion"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."handle_appointment_financial_snapshot"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
    IF OLD.status = 'completed' THEN
        RETURN NEW;
    END IF;
    IF (TG_OP = 'INSERT') OR (NEW.service_id IS DISTINCT FROM OLD.service_id) THEN
        IF NEW.price IS NULL OR (TG_OP = 'UPDATE' AND NEW.price = OLD.price) THEN
            SELECT price, cost INTO NEW.price, NEW.cost
            FROM public.services WHERE id = NEW.service_id;
        END IF;
    END IF;
    IF (TG_OP = 'INSERT') OR (NEW.barber_id IS DISTINCT FROM OLD.barber_id) THEN
        IF NEW.commission_rate IS NULL OR (TG_OP = 'UPDATE' AND NEW.commission_rate = OLD.commission_rate) THEN
            SELECT commission_rate INTO NEW.commission_rate
            FROM public.barbers WHERE id = NEW.barber_id;
        END IF;
    END IF;
    IF NEW.price IS NULL THEN NEW.price := 0; END IF;
    IF NEW.cost IS NULL THEN NEW.cost := 0; END IF;
    IF NEW.commission_rate IS NULL THEN NEW.commission_rate := 50; END IF;
    RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."handle_appointment_financial_snapshot"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."handle_new_user"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_phone text;
  v_retry_count int := 0;
  v_max_retries int := 3;
BEGIN
  -- Extract phone from metadata or directly from auth (WhatsApp login usually sets phone)
  v_phone := NEW.phone;
  IF v_phone IS NULL THEN
     v_phone := NEW.raw_user_meta_data->>'phone_number';
  END IF;

  -- Default retry loop logic for high concurrency (just in case)
  LOOP
    BEGIN
      INSERT INTO public.profiles (id, full_name, role, phone, email)
      VALUES (
        NEW.id,
        COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.raw_user_meta_data->>'name', 'Usuário Novo'),
        COALESCE(NEW.raw_user_meta_data->>'role', 'customer'),
        v_phone,
        NEW.email -- Important for the shadow email logic
      )
      ON CONFLICT (id) DO UPDATE
      SET
        email = EXCLUDED.email,
        phone = COALESCE(public.profiles.phone, EXCLUDED.phone), -- Keep existing phone if present
        updated_at = now();
        
      -- If successful, break loop
      EXIT;
      
    EXCEPTION WHEN unique_violation THEN
      -- Handle race conditions
      IF v_retry_count < v_max_retries THEN
        v_retry_count := v_retry_count + 1;
        PERFORM pg_sleep(0.1); -- Wait 100ms
        CONTINUE;
      ELSE
        RAISE WARNING 'Failed to create profile for user % after retries', NEW.id;
        RETURN NEW;
      END IF;
    WHEN OTHERS THEN
       -- Log error but allow auth user creation to proceed (don't block signup)
       -- We can use a hypothetical logs table, or just RAISE WARNING
       RAISE WARNING 'Error in handle_new_user for %: %', NEW.id, SQLERRM;
       RETURN NEW;
    END;
  END LOOP;

  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."handle_new_user"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."handle_updated_at"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."handle_updated_at"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."has_barbershop_role"("_user_id" "uuid", "_barbershop_id" "uuid", "_role" "public"."app_role") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.user_roles
    WHERE user_id = _user_id 
      AND barbershop_id = _barbershop_id 
      AND role = _role
  )
$$;


ALTER FUNCTION "public"."has_barbershop_role"("_user_id" "uuid", "_barbershop_id" "uuid", "_role" "public"."app_role") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."has_role"("_user_id" "uuid", "_role" "public"."app_role") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.user_roles
    WHERE user_id = _user_id AND role = _role
  )
$$;


ALTER FUNCTION "public"."has_role"("_user_id" "uuid", "_role" "public"."app_role") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."health_check"() RETURNS json
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
begin
  return json_build_object(
    'status', 'ok',
    'timestamp', now(),
    'version', 'v39-savior'
  );
end;
$$;


ALTER FUNCTION "public"."health_check"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."is_account_locked_internal"("p_email" "text") RETURNS boolean
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'pg_catalog', 'public', 'pg_temp'
    AS $$
DECLARE
  v_failed_attempts_15m INTEGER;
  v_failed_attempts_1h  INTEGER;
  v_failed_attempts_24h INTEGER;
BEGIN
  -- Use a single efficient query with conditional counts
  SELECT
    COUNT(*) FILTER (WHERE attempted_at > NOW() - INTERVAL '15 minutes'),
    COUNT(*) FILTER (WHERE attempted_at > NOW() - INTERVAL '1 hour'),
    COUNT(*)
  INTO
    v_failed_attempts_15m,
    v_failed_attempts_1h,
    v_failed_attempts_24h
  FROM public.login_attempts
  WHERE email = lower(p_email)
    AND success = false
    AND attempted_at > NOW() - INTERVAL '24 hours';

  -- Progressive lockout: most recent window checked first for efficiency
  IF v_failed_attempts_15m >= 5 THEN
    RETURN true;  -- Lockout: 15min threshold
  END IF;

  IF v_failed_attempts_1h >= 10 THEN
    RETURN true;  -- Lockout: 1hr threshold
  END IF;

  IF v_failed_attempts_24h >= 20 THEN
    RETURN true;  -- Lockout: 24hr threshold
  END IF;

  RETURN false;
END;
$$;


ALTER FUNCTION "public"."is_account_locked_internal"("p_email" "text") OWNER TO "postgres";


COMMENT ON FUNCTION "public"."is_account_locked_internal"("p_email" "text") IS '[SOVEREIGN V4.9] Server-side lockout check. INTERNAL USE ONLY.
Called by auth hooks and Edge Functions. Revoked from anon/authenticated
to prevent email enumeration via timing attacks. Fixes V-20, V-21.';



CREATE OR REPLACE FUNCTION "public"."is_system_locked"("p_key" "text" DEFAULT 'maintenance_mode'::"text") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    AS $$
    SELECT COALESCE((value::TEXT = 'true'), false) 
    FROM public.system_settings 
    WHERE key = p_key;
$$;


ALTER FUNCTION "public"."is_system_locked"("p_key" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."is_valid_email"("p_email" "text") RETURNS boolean
    LANGUAGE "plpgsql" IMMUTABLE
    AS $_$
BEGIN
  -- Validação básica de email usando regex
  IF p_email IS NULL OR p_email = '' THEN
    RETURN FALSE;
  END IF;
  
  -- Regex básico para email (pode ser melhorado)
  RETURN p_email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$';
END;
$_$;


ALTER FUNCTION "public"."is_valid_email"("p_email" "text") OWNER TO "postgres";


COMMENT ON FUNCTION "public"."is_valid_email"("p_email" "text") IS 'Valida formato de email usando regex. Retorna TRUE se válido, FALSE caso contrário.';



CREATE OR REPLACE FUNCTION "public"."log_audit_event"("p_table_name" "text", "p_record_id" "uuid", "p_action" "text", "p_category" "text", "p_old_data" "jsonb" DEFAULT NULL::"jsonb", "p_new_data" "jsonb" DEFAULT NULL::"jsonb") RETURNS "uuid"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_log_id uuid;
  v_user_id uuid;
  v_metadata jsonb;
BEGIN
  v_user_id := auth.uid();
  
  -- Validação de sanidade (evitamos restringir a INSERT/UPDATE/DELETE apenas, para suportar regras de negócio)
  IF p_action IS NULL OR trim(p_action) = '' THEN
    RAISE EXCEPTION 'log_audit_event: p_action cannot be empty';
  END IF;

  -- Empacotar todos os dados variáveis no metadata.
  -- É fundamental usar jsonb_strip_nulls para não inflacionar os dados.
  v_metadata := jsonb_strip_nulls(jsonb_build_object(
    'table_name', p_table_name,
    'record_id', p_record_id,
    'category', p_category,
    'old_data', p_old_data,
    'new_data', p_new_data
  ));
  
  -- Inserimos apenas nas colunas que ESTRITAMENTE existem no schema public.audit_logs
  -- action, user_id, metadata, level, created_at
  INSERT INTO public.audit_logs (
    action, 
    user_id, 
    metadata, 
    level, 
    created_at
  ) VALUES (
    p_table_name || '.' || p_action, 
    COALESCE(v_user_id, '00000000-0000-0000-0000-000000000000'::uuid),
    v_metadata,
    'info'::audit_level,
    NOW()
  )
  RETURNING id INTO v_log_id;
  
  RETURN v_log_id;
END;
$$;


ALTER FUNCTION "public"."log_audit_event"("p_table_name" "text", "p_record_id" "uuid", "p_action" "text", "p_category" "text", "p_old_data" "jsonb", "p_new_data" "jsonb") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."log_mfa_event"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
BEGIN
    INSERT INTO public.audit_logs (action, level, description, metadata)
    VALUES (
        'mfa_verification',
        'info',
        'User MFA verification successful',
        jsonb_build_object('user_id', auth.uid(), 'aal', auth.jwt() ->> 'aal')
    );
    RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."log_mfa_event"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."log_security_event"("p_type" "text", "p_severity" "text", "p_user_id" "uuid", "p_ip_address" "text", "p_details" "jsonb") RETURNS "void"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
BEGIN
  IF p_severity NOT IN ('low', 'medium', 'high', 'critical') THEN
    RAISE EXCEPTION 'Invalid severity: %. Must be low, medium, high, or critical', p_severity;
  END IF;
  
  INSERT INTO public.security_events (
    type, severity, user_id, ip_address, details, created_at
  ) VALUES (
    p_type, p_severity, p_user_id, p_ip_address, p_details, NOW()
  );
END;
$$;


ALTER FUNCTION "public"."log_security_event"("p_type" "text", "p_severity" "text", "p_user_id" "uuid", "p_ip_address" "text", "p_details" "jsonb") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."log_sovereign_batch_v2"("p_events" "jsonb"[]) RETURNS "uuid"[]
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_log_ids uuid[] := '{}';
  v_event jsonb;
  v_log_id uuid;
  v_user_id uuid;
BEGIN
  v_user_id := auth.uid();
  
  FOREACH v_event IN ARRAY p_events
  LOOP
    IF NOT (v_event ? 'action' AND v_event ? 'level' AND v_event ? 'description') THEN
      RAISE EXCEPTION 'Event missing required fields: %', v_event;
    END IF;
    
    INSERT INTO public.sovereign_audit_logs (
      action, level, description, metadata, user_id, created_at
    ) VALUES (
      v_event->>'action',
      v_event->>'level',
      v_event->>'description',
      COALESCE(v_event->'metadata', '{}'::jsonb),
      COALESCE((v_event->>'user_id')::uuid, v_user_id),
      NOW()
    )
    RETURNING id INTO v_log_id;
    
    v_log_ids := array_append(v_log_ids, v_log_id);
  END LOOP;
  
  RETURN v_log_ids;
END;
$$;


ALTER FUNCTION "public"."log_sovereign_batch_v2"("p_events" "jsonb"[]) OWNER TO "postgres";


COMMENT ON FUNCTION "public"."log_sovereign_batch_v2"("p_events" "jsonb"[]) IS 'High-Throughput Batch Ingestion. Prevents connection exhaustion. Accepts JSONB[].';



CREATE OR REPLACE FUNCTION "public"."log_sovereign_event"("p_action" "text", "p_level" "text", "p_description" "text", "p_metadata" "jsonb" DEFAULT '{}'::"jsonb", "p_user_id" "uuid" DEFAULT NULL::"uuid") RETURNS "uuid"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
    v_log_id UUID;
    v_ip TEXT;
    v_final_user_id UUID;
    v_role TEXT;
BEGIN
    v_role := auth.role();

    -- 🛡️ SECURITY CHECK (Hacker Defense)
    IF v_role = 'anon' THEN
        IF p_action NOT IN ('login_failed', 'signup_error', 'password_reset_request', 'otp_request') THEN
            -- Silent Reject (Don't give info to attacker) OR Raise Exception
            -- Raising exception is better for debugging client issues.
            RAISE EXCEPTION 'Anonymous logging restricted for action: %', p_action;
        END IF;
    END IF;

    v_ip := current_setting('request.headers', true)::json->>'x-forwarded-for';
    v_final_user_id := COALESCE(p_user_id, auth.uid());

    INSERT INTO public.audit_logs (
        action,
        level,
        description,
        metadata,
        user_id,
        ip_address
    ) VALUES (
        p_action,
        p_level,
        p_description,
        p_metadata,
        v_final_user_id,
        v_ip
    )
    RETURNING id INTO v_log_id;

    RETURN v_log_id;
END;
$$;


ALTER FUNCTION "public"."log_sovereign_event"("p_action" "text", "p_level" "text", "p_description" "text", "p_metadata" "jsonb", "p_user_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."log_sovereign_event_v2"("p_action" "text", "p_level" "public"."audit_level", "p_description" "text", "p_metadata" "jsonb" DEFAULT '{}'::"jsonb", "p_user_id" "uuid" DEFAULT NULL::"uuid") RETURNS "uuid"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_log_id uuid;
  v_user_id uuid;
BEGIN
  v_user_id := COALESCE(p_user_id, auth.uid());
  
  INSERT INTO public.sovereign_audit_logs (
    action, level, description, metadata, user_id, created_at
  ) VALUES (
    p_action, p_level::text, p_description, p_metadata, v_user_id, NOW()
  )
  RETURNING id INTO v_log_id;
  
  RETURN v_log_id;
END;
$$;


ALTER FUNCTION "public"."log_sovereign_event_v2"("p_action" "text", "p_level" "public"."audit_level", "p_description" "text", "p_metadata" "jsonb", "p_user_id" "uuid") OWNER TO "postgres";


COMMENT ON FUNCTION "public"."log_sovereign_event_v2"("p_action" "text", "p_level" "public"."audit_level", "p_description" "text", "p_metadata" "jsonb", "p_user_id" "uuid") IS 'Primary Audit RPC. Enforces ENUM types. Hardened.';



CREATE OR REPLACE FUNCTION "public"."mark_event_as_alerted"("p_event_id" "uuid") RETURNS boolean
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_updated boolean;
BEGIN
  UPDATE public.security_events
  SET alerted_at = NOW()
  WHERE id = p_event_id
    AND alerted_at IS NULL;
  
  GET DIAGNOSTICS v_updated = ROW_COUNT;
  
  RETURN v_updated > 0;
END;
$$;


ALTER FUNCTION "public"."mark_event_as_alerted"("p_event_id" "uuid") OWNER TO "postgres";


COMMENT ON FUNCTION "public"."mark_event_as_alerted"("p_event_id" "uuid") IS 'Marks a security event as having triggered an alert. SECURITY INVOKER - RLS enforced. Week 3A migration.';


SET default_tablespace = '';

SET default_table_access_method = "heap";


CREATE TABLE IF NOT EXISTS "public"."webhook_events" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "event_type" "text" NOT NULL,
    "payload" "jsonb" NOT NULL,
    "status" "text" DEFAULT 'pending'::"text" NOT NULL,
    "retry_count" integer DEFAULT 0,
    "last_error" "text",
    "processed_at" timestamp with time zone,
    "next_retry_at" timestamp with time zone DEFAULT "now"(),
    "worker_id" "uuid",
    "last_heartbeat" timestamp with time zone,
    CONSTRAINT "webhook_events_status_check" CHECK (("status" = ANY (ARRAY['pending'::"text", 'processing'::"text", 'completed'::"text", 'failed'::"text"])))
);


ALTER TABLE "public"."webhook_events" OWNER TO "postgres";


COMMENT ON TABLE "public"."webhook_events" IS 'VUL-016 REMEDIADO (2025): RLS ativado. Acesso exclusivo via service_role (Edge Functions). Nenhum user autenticado/anon pode ler ou escrever diretamente.';



COMMENT ON COLUMN "public"."webhook_events"."event_type" IS 'Stripe or MegaAPI event types. megaapi.ack requires specific dispatcher.';



CREATE OR REPLACE FUNCTION "public"."pick_next_webhook_event"("p_worker_id" "uuid") RETURNS SETOF "public"."webhook_events"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
BEGIN
    RETURN QUERY
    UPDATE public.webhook_events
    SET 
        status = 'processing',
        worker_id = p_worker_id,
        last_heartbeat = now(),
        processed_at = NULL -- Reset processed_at if it was previously failed/ignored
    WHERE id = (
        SELECT id 
        FROM public.webhook_events
        WHERE 
            (status = 'pending' AND next_retry_at <= now())
            OR (status = 'processing' AND last_heartbeat < now() - interval '5 minutes') -- Zombie Recovery
        ORDER BY created_at ASC
        LIMIT 1
        FOR UPDATE SKIP LOCKED
    )
    RETURNING *;
END;
$$;


ALTER FUNCTION "public"."pick_next_webhook_event"("p_worker_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."prevent_barber_hard_delete"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM public.appointments WHERE barber_id = OLD.id) THEN
        RAISE EXCEPTION 'Cannot hard-delete Barber with existing appointments. Use soft-delete (deleted_at).';
    END IF;
    RETURN OLD;
END;
$$;


ALTER FUNCTION "public"."prevent_barber_hard_delete"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."prevent_log_manipulation"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
    RAISE EXCEPTION 'AUDIT LOG INTEGRITY: Logs are immutable and cannot be modified or deleted.';
END;
$$;


ALTER FUNCTION "public"."prevent_log_manipulation"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."prevent_log_manipulation_backup"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
BEGIN
    RAISE EXCEPTION 'Audit Logs are immutable. UPDATE and DELETE are strictly forbidden. (Sovereign Spec 1.1)';
END;
$$;


ALTER FUNCTION "public"."prevent_log_manipulation_backup"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."prevent_role_escalation"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
      BEGIN
        -- Allow Service Role AND Postgres (Admin) to bypass
        -- NEW: Allow explicitly flagged System Functions to bypass
        IF (auth.role() = 'service_role') 
           OR (current_user IN ('postgres', 'supabase_admin')) 
           OR (current_setting('app.bypass_role_guard', true) = 'on') THEN
            RETURN new;
        END IF;

        RAISE EXCEPTION 'SECURITY ALERT: Access Denied. You cannot modify user roles.';
      END;
      $$;


ALTER FUNCTION "public"."prevent_role_escalation"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."prevent_sensitive_updates"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
begin
  if (auth.role() = 'service_role') then return new; end if;
  if (new.subscription_plan is distinct from old.subscription_plan) or
     (new.subscription_status is distinct from old.subscription_status) or
     (new.subscription_ends_at is distinct from old.subscription_ends_at) then
      raise exception 'SECURITY ALERT: Access Denied. You cannot modify subscription billing fields directly.';
  end if;
  return new;
end;
$$;


ALTER FUNCTION "public"."prevent_sensitive_updates"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."prevent_service_hard_delete"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM public.appointments WHERE service_id = OLD.id) THEN
        RAISE EXCEPTION 'Cannot hard-delete Service with existing appointments. Use soft-delete (deleted_at).';
    END IF;
    RETURN OLD;
END;
$$;


ALTER FUNCTION "public"."prevent_service_hard_delete"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."process_checkout_atomic"("p_appointment_id" "uuid", "p_cart_items" "jsonb", "p_payment_method" "text", "p_service_price" numeric, "p_products_total" numeric, "p_total_amount" numeric, "p_discount" numeric, "p_final_amount" numeric) RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_appointment RECORD;
  v_barber RECORD;
  v_sale_id UUID;
  v_item JSONB;
  v_product_id UUID;
  v_quantity INTEGER;
  v_commission_amount NUMERIC;
  v_commission_rate NUMERIC;
  v_caller_id UUID := auth.uid();
BEGIN
  -- 1. 🔒 Lock & Load Appointment with Ownership Check
  -- Unifica a validação de existência e de permissão (IDOR Fix)
  SELECT a.* INTO v_appointment
  FROM appointments a
  JOIN barbershops b ON a.barbershop_id = b.id
  WHERE a.id = p_appointment_id
    AND (
        b.owner_id = v_caller_id 
        OR EXISTS (SELECT 1 FROM profiles WHERE id = v_caller_id AND role = 'admin')
    )
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Agendamento não encontrado ou acesso negado.';
  END IF;

  -- 2. 🛑 Idempotency Check
  IF v_appointment.status = 'completed' OR v_appointment.payment_status = 'paid' THEN
    RETURN jsonb_build_object(
      'success', true, 
      'already_processed', true,
      'message', 'Agendamento já finalizado.'
    );
  END IF;

  -- 3. 💾 Create Sale Record
  INSERT INTO sales (
    barbershop_id,
    appointment_id,
    customer_id,
    barber_id,
    payment_method,
    total_amount,
    discount_amount,
    final_amount,
    payment_status,
    created_at
  ) VALUES (
    v_appointment.barbershop_id,
    v_appointment.id,
    v_appointment.customer_id,
    v_appointment.barber_id,
    p_payment_method,
    p_total_amount,
    p_discount,
    p_final_amount,
    'paid',
    NOW()
  ) RETURNING id INTO v_sale_id;

  -- 4. 📦 Process Cart Items (Products) with Tenant Isolation
  FOR v_item IN SELECT * FROM jsonb_array_elements(p_cart_items)
  LOOP
    v_product_id := (v_item->>'product_id')::UUID;
    v_quantity := (v_item->>'quantity')::INTEGER;

    -- Update Stock & Check Availability (Atomic Decrement)
    UPDATE products
    SET stock_quantity = stock_quantity - v_quantity
    WHERE id = v_product_id
      AND barbershop_id = v_appointment.barbershop_id -- 🛡️ Fix IDOR: Isolamento de Estoque Cross-Tenant
      AND stock_quantity >= v_quantity;
    
    IF NOT FOUND THEN
      RAISE EXCEPTION 'Produto não encontrado ou estoque insuficiente na sua barbearia.';
    END IF;

    -- Insert Sale Item
    INSERT INTO sale_items (
      sale_id,
      product_id,
      product_name,
      quantity,
      unit_price,
      total_price
    ) VALUES (
      v_sale_id,
      v_product_id,
      v_item->>'product_name',
      v_quantity,
      (v_item->>'unit_price')::NUMERIC,
      (v_item->>'total_price')::NUMERIC
    );
  END LOOP;

  -- 5. 💰 Calculate & Create Commission
  SELECT commission_percentage INTO v_barber
  FROM barbers
  WHERE id = v_appointment.barber_id;
  v_commission_rate := COALESCE(v_barber.commission_percentage, 0);
  
  v_commission_amount := (p_service_price * v_commission_rate) / 100;
  IF v_commission_amount > 0 THEN
    INSERT INTO commissions (
      barbershop_id,
      barber_id,
      appointment_id,
      sale_id,
      service_amount,
      product_amount,
      commission_percentage,
      commission_amount,
      reference_date,
      is_paid,
      created_at
    ) VALUES (
      v_appointment.barbershop_id,
      v_appointment.barber_id,
      v_appointment.id,
      v_sale_id,
      p_service_price,
      0,
      v_rule_applied, -- Ajustado para manter compatibilidade com schema
      v_commission_amount,
      CURRENT_DATE,
      false,
      NOW()
    );
  END IF;

  -- 6. ✅ Update Appointment Status
  UPDATE appointments
  SET 
    status = 'completed',
    payment_status = 'paid',
    payment_method = p_payment_method,
    final_amount = p_final_amount,
    updated_at = NOW()
  WHERE id = p_appointment_id;

  RETURN jsonb_build_object(
    'success', true, 
    'sale_id', v_sale_id,
    'message', 'Checkout realizado com sucesso.'
  );

EXCEPTION WHEN OTHERS THEN
  RETURN jsonb_build_object(
    'success', false,
    'error', SQLERRM
  );
END;
$$;


ALTER FUNCTION "public"."process_checkout_atomic"("p_appointment_id" "uuid", "p_cart_items" "jsonb", "p_payment_method" "text", "p_service_price" numeric, "p_products_total" numeric, "p_total_amount" numeric, "p_discount" numeric, "p_final_amount" numeric) OWNER TO "postgres";


COMMENT ON FUNCTION "public"."process_checkout_atomic"("p_appointment_id" "uuid", "p_cart_items" "jsonb", "p_payment_method" "text", "p_service_price" numeric, "p_products_total" numeric, "p_total_amount" numeric, "p_discount" numeric, "p_final_amount" numeric) IS 'RPC atômico para processar checkout completo. Inclui: criação de venda, itens, atualização de estoque COM LOCK, cálculo de comissão e atualização de agendamento. Tudo em uma transação ACID com rollback automático em caso de erro. Previne race conditions e duplicações.';



CREATE OR REPLACE FUNCTION "public"."process_checkout_atomic"("p_appointment_id" "uuid", "p_cart_items" "public"."checkout_item"[], "p_payment_method" "text", "p_service_price" numeric, "p_products_total" numeric, "p_total_amount" numeric, "p_discount" numeric, "p_final_amount" numeric) RETURNS json
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public', 'loyalty'
    AS $$
DECLARE
    v_appointment RECORD;
    v_item checkout_item;
    v_points_added INTEGER := 0;
    v_loyalty_program RECORD;
    v_user_id UUID;
    v_actor TEXT := 'staff';
    v_real_service_price NUMERIC(10,2) := 0;
    v_real_products_total NUMERIC(10,2) := 0;
    v_product RECORD;
BEGIN
    v_user_id := auth.uid();

    -- A. ROW LOCK The Appointment (Prevent Double Checkout)
    SELECT a.* INTO v_appointment
    FROM public.appointments a
    WHERE a.id = p_appointment_id
    FOR UPDATE;

    IF v_appointment IS NULL THEN RAISE EXCEPTION 'APPOINTMENT_NOT_FOUND'; END IF;
    IF v_appointment.status = 'completed' THEN 
        RETURN json_build_object('success', true, 'already_processed', true);
    END IF;

    -- B. TRUE ZERO TRUST: Compute the actual prices from the database
    -- Get the real service price (V13 introduced 'price' snapshot in appointments, fallback to services)
    IF v_appointment.price IS NOT NULL THEN
        v_real_service_price := v_appointment.price;
    ELSE
        SELECT price INTO v_real_service_price FROM public.services WHERE id = v_appointment.service_id;
    END IF;

    v_real_service_price := COALESCE(v_real_service_price, 0);

    -- C. Decrease Product Stock & Calculate Real Products Total
    IF array_length(p_cart_items, 1) > 0 THEN
        FOREACH v_item IN ARRAY p_cart_items
        LOOP
            IF v_item.product_id IS NOT NULL THEN
                -- Fetch & Lock the product
                SELECT * INTO v_product 
                FROM public.products 
                WHERE id = v_item.product_id 
                FOR UPDATE;

                IF v_product IS NULL THEN
                    RAISE EXCEPTION 'PRODUCT_NOT_FOUND: %', v_item.product_id;
                END IF;

                IF v_product.stock_quantity < v_item.quantity THEN
                    RAISE EXCEPTION 'INSUFFICIENT_STOCK: Não há % unidades de "%"', v_item.quantity, v_product.name;
                END IF;

                -- Accumulate real cost from the SERVER's price
                v_real_products_total := v_real_products_total + (v_product.price * v_item.quantity);

                -- Deduct the stock
                UPDATE public.products 
                SET 
                    stock_quantity = stock_quantity - v_item.quantity,
                    updated_at = NOW()
                WHERE id = v_item.product_id;
            END IF;
        END LOOP;
    END IF;

    -- D. Verify the Math against the REAL computed values
    IF (v_real_service_price + v_real_products_total - p_discount) <> p_final_amount THEN
        RAISE EXCEPTION 'TRUE_ZERO_TRUST_MISMATCH: Computed final % vs Requested %', (v_real_service_price + v_real_products_total - p_discount), p_final_amount;
    END IF;

    -- D. Mark Appointment Completed
    UPDATE public.appointments 
    SET 
        status = 'completed',
        total_amount = p_total_amount,
        final_amount = p_final_amount,
        discount_amount = p_discount,
        payment_method = p_payment_method,
        updated_at = NOW()
    WHERE id = p_appointment_id;

    -- D.1. Register Product Revenue in Ledger (Zero Fallacy P&L Fix)
    IF v_real_products_total > 0 THEN
        INSERT INTO public.financial_ledger (
            barbershop_id,
            appointment_id,
            appointment_date,
            barber_id,
            transaction_type,
            amount,
            description,
            status
        ) VALUES (
            v_appointment.barbershop_id,
            p_appointment_id,
            v_appointment.appointment_date,
            v_appointment.barber_id,
            'income',
            v_real_products_total,
            'Receita de Produtos (Checkout #' || substring(p_appointment_id::text, 1, 8) || ')',
            'completed'
        );
    END IF;

    -- E. Add Loyalty Points
    -- Optional context (may not exist in early v1 instances, wrapping safely)
    IF EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_schema = 'loyalty' AND table_name = 'programs'
    ) THEN
        SELECT p.* INTO v_loyalty_program 
        FROM loyalty.programs p 
        WHERE p.barbershop_id = v_appointment.barbershop_id AND p.enabled = true;

        IF v_loyalty_program IS NOT NULL AND v_appointment.customer_id IS NOT NULL THEN
            v_points_added := v_loyalty_program.points_per_service;
            
            INSERT INTO public.loyalty_points (
                customer_id, 
                barbershop_id, 
                points, 
                total_earned
            ) VALUES (
                v_appointment.customer_id, 
                v_appointment.barbershop_id, 
                v_points_added, 
                v_points_added
            )
            ON CONFLICT (customer_id, barbershop_id) 
            DO UPDATE SET 
                points = loyalty_points.points + v_points_added,
                total_earned = loyalty_points.total_earned + v_points_added,
                updated_at = NOW();
        END IF;
    END IF;

    -- F. Register in Audit Log
    -- If using Sovereign Jobs (V22) push to job queue for reports/email
    IF EXISTS (SELECT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'sovereign_jobs') THEN
        INSERT INTO public.sovereign_jobs (payload)
        VALUES (jsonb_build_object(
            'type', 'checkout_completed',
            'appointmentId', p_appointment_id,
            'finalAmount', p_final_amount,
            'pointsAdded', v_points_added
        ));
    END IF;

    RETURN json_build_object(
        'success', true, 
        'transaction_id', p_appointment_id,
        'points_added', v_points_added
    );

EXCEPTION
    WHEN OTHERS THEN
        RAISE EXCEPTION 'ATOMIC_CHECKOUT_FAILED: %', SQLERRM;
END;
$$;


ALTER FUNCTION "public"."process_checkout_atomic"("p_appointment_id" "uuid", "p_cart_items" "public"."checkout_item"[], "p_payment_method" "text", "p_service_price" numeric, "p_products_total" numeric, "p_total_amount" numeric, "p_discount" numeric, "p_final_amount" numeric) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."protect_immutability_trigger"() RETURNS "event_trigger"
    LANGUAGE "plpgsql"
    AS $$
DECLARE
    obj RECORD;
    cmd TEXT;
BEGIN
    -- Get the command being executed
    FOR obj IN SELECT * FROM pg_event_trigger_ddl_commands() LOOP
        -- Check if it's an ALTER TABLE command affecting our trigger
        IF obj.command_tag = 'ALTER TABLE' THEN
            -- Get the full command text
            cmd := current_query();
            
            -- Block attempts to disable the immutability trigger
            IF cmd ILIKE '%DISABLE TRIGGER%trg_audit_logs_immutable%' OR
               cmd ILIKE '%DROP TRIGGER%trg_audit_logs_immutable%' THEN
                RAISE EXCEPTION 'Cannot disable or drop immutability trigger (Sovereign Spec 1.1 - Invariant: Immutability)';
            END IF;
        END IF;
    END LOOP;
END;
$$;


ALTER FUNCTION "public"."protect_immutability_trigger"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."queue_whatsapp_notification"("p_appointment_id" "uuid", "p_phone_number" "text", "p_message_type" "text", "p_template_data" "jsonb") RETURNS json
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
  -- Validate Appointment exists (Security Check)
  IF NOT EXISTS (SELECT 1 FROM public.appointments WHERE id = p_appointment_id) THEN
    RAISE EXCEPTION 'Invalid Appointment ID';
  END IF;
  INSERT INTO public.whatsapp_retry_queue (
    appointment_id,
    phone_number,
    message_type,
    template_data,
    status,
    retry_count,
    next_retry_at
  ) VALUES (
    p_appointment_id,
    p_phone_number,
    p_message_type,
    p_template_data,
    'pending',
    0,
    NOW() + INTERVAL '5 minutes'
  );
  RETURN json_build_object('success', true);
EXCEPTION WHEN OTHERS THEN
  RETURN json_build_object('success', false, 'error', SQLERRM);
END;
$$;


ALTER FUNCTION "public"."queue_whatsapp_notification"("p_appointment_id" "uuid", "p_phone_number" "text", "p_message_type" "text", "p_template_data" "jsonb") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."reconcile_bi_metrics"("p_date" "date") RETURNS TABLE("metric_name" "text", "operational_value" numeric, "bi_value" numeric, "discrepancy" numeric, "status" "text")
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_op_revenue numeric;
  v_bi_revenue numeric;
  v_op_appointments integer;
  v_bi_appointments integer;
BEGIN
  -- 1. Calculate Revenue from Operational Data (payments table)
  SELECT COALESCE(SUM(amount), 0)
  INTO v_op_revenue
  FROM public.payments
  WHERE date(created_at) = p_date
    AND status = 'completed';

  -- 2. Calculate Revenue from BI Data (daily_metrics table)
  SELECT COALESCE(total_revenue, 0)
  INTO v_bi_revenue
  FROM public.daily_metrics
  WHERE date = p_date
    AND shop_id IS NULL; -- Global metric

  -- 3. Calculate Appointments from Operational Data
  SELECT COUNT(*)
  INTO v_op_appointments
  FROM public.appointments
  WHERE date(start_time) = p_date;

  -- 4. Calculate Appointments from BI Data
  SELECT COALESCE(total_appointments, 0)
  INTO v_bi_appointments
  FROM public.daily_metrics
  WHERE date = p_date
    AND shop_id IS NULL;

  -- Return results
  RETURN QUERY SELECT 
    'total_revenue'::text,
    v_op_revenue,
    v_bi_revenue,
    (v_op_revenue - v_bi_revenue),
    CASE WHEN v_op_revenue = v_bi_revenue THEN 'matched' ELSE 'mismatch' END;

  RETURN QUERY SELECT 
    'total_appointments'::text,
    v_op_appointments::numeric,
    v_bi_appointments::numeric,
    (v_op_appointments - v_bi_appointments)::numeric,
    CASE WHEN v_op_appointments = v_bi_appointments THEN 'matched' ELSE 'mismatch' END;
END;
$$;


ALTER FUNCTION "public"."reconcile_bi_metrics"("p_date" "date") OWNER TO "postgres";


COMMENT ON FUNCTION "public"."reconcile_bi_metrics"("p_date" "date") IS 'Reconciles operational vs BI data. SECURITY INVOKER - RLS enforced. Week 3B migration.';



CREATE OR REPLACE FUNCTION "public"."reconcile_bi_metrics"("p_barbershop_id" "uuid", "p_date" "date") RETURNS TABLE("old_appointments" bigint, "new_appointments" bigint, "old_revenue" numeric, "new_revenue" numeric)
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
    v_new_appointments BIGINT;
    v_new_revenue NUMERIC;
    v_old_appointments BIGINT;
    v_old_revenue NUMERIC;
BEGIN
    -- 1. Calculate Truth from appointments table
    SELECT 
        COUNT(*),
        COALESCE(SUM(price), 0)
    INTO v_new_appointments, v_new_revenue
    FROM public.appointments
    WHERE barbershop_id = p_barbershop_id
      AND appointment_date = p_date
      AND status = 'confirmed';

    -- 2. Capture Old Values
    SELECT 
        appointments_count,
        revenue
    INTO v_old_appointments, v_old_revenue
    FROM public.daily_metrics
    WHERE barbershop_id = p_barbershop_id
      AND date = p_date;

    -- 3. Update (Overwrite) with Truth
    INSERT INTO public.daily_metrics (barbershop_id, date, appointments_count, revenue)
    VALUES (p_barbershop_id, p_date, v_new_appointments, v_new_revenue)
    ON CONFLICT (barbershop_id, date)
    DO UPDATE SET
        appointments_count = EXCLUDED.appointments_count,
        revenue = EXCLUDED.revenue,
        updated_at = now();

    RETURN QUERY SELECT 
        COALESCE(v_old_appointments, 0), 
        v_new_appointments, 
        COALESCE(v_old_revenue, 0), 
        v_new_revenue;
END;
$$;


ALTER FUNCTION "public"."reconcile_bi_metrics"("p_barbershop_id" "uuid", "p_date" "date") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."reconcile_bi_month"("p_barbershop_id" "uuid", "p_month" "date") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
    v_date DATE;
BEGIN
    FOR v_date IN 
        SELECT generate_series(
            date_trunc('month', p_month)::date,
            (date_trunc('month', p_month) + interval '1 month' - interval '1 day')::date,
            interval '1 day'
        )::date
    LOOP
        PERFORM public.reconcile_bi_metrics(p_barbershop_id, v_date);
    END LOOP;
END;
$$;


ALTER FUNCTION "public"."reconcile_bi_month"("p_barbershop_id" "uuid", "p_month" "date") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."record_login_attempt"("p_email" "text", "p_success" boolean, "p_ip" "text" DEFAULT 'unknown'::"text") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'pg_catalog', 'public', 'pg_temp'
    AS $$
BEGIN
  -- Only record failures (successes don't need tracking for lockout purposes)
  -- Normalize email to lowercase to prevent case-sensitivity bypass
  INSERT INTO public.login_attempts (email, ip_address, success, attempted_at)
  VALUES (lower(p_email), p_ip, p_success, NOW());

  -- Auto-cleanup: purge attempts older than 48h to prevent table bloat
  -- Uses a probabilistic cleanup (1 in 50 calls) to avoid every call doing cleanup
  IF random() < 0.02 THEN
    DELETE FROM public.login_attempts
    WHERE attempted_at < NOW() - INTERVAL '48 hours';
  END IF;
END;
$$;


ALTER FUNCTION "public"."record_login_attempt"("p_email" "text", "p_success" boolean, "p_ip" "text") OWNER TO "postgres";


COMMENT ON FUNCTION "public"."record_login_attempt"("p_email" "text", "p_success" boolean, "p_ip" "text") IS '[SOVEREIGN V4.9] Safe write surface for login attempt tracking.
INSERT-only (via SECURITY DEFINER). Normalizes email. Includes probabilistic
self-cleanup for table hygiene. Replaces direct table access.';



CREATE OR REPLACE FUNCTION "public"."reschedule_appointment"("p_old_appointment_id" "uuid", "p_new_date" "date", "p_new_time" time without time zone, "p_new_barber_id" "uuid" DEFAULT NULL::"uuid", "p_new_service_id" "uuid" DEFAULT NULL::"uuid", "p_token" "text" DEFAULT NULL::"text", "p_auth_user_id" "uuid" DEFAULT NULL::"uuid") RETURNS json
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_old_appointment RECORD;
  v_new_barber_id UUID;
  v_new_service_id UUID;
  v_service_duration INTEGER;
  v_service_padding INTEGER := 0; 
  v_has_conflict BOOLEAN;
  v_new_appointment_id UUID;
  v_new_token TEXT;
  v_queue_payload jsonb;
  v_lock_id_1 integer;
  v_lock_id_2 integer;
BEGIN
  SELECT a.*, b.name as barbershop_name, b.address as barbershop_address,
         c.name as customer_name, c.phone as customer_phone, bar.name as barber_name,
         s.name as service_name
  INTO v_old_appointment 
  FROM appointments a 
  JOIN barbershops b ON a.barbershop_id = b.id
  JOIN customers c ON a.customer_id = c.id
  JOIN services s ON a.service_id = s.id
  JOIN barbers bar ON a.barber_id = bar.id
  WHERE a.id = p_old_appointment_id FOR UPDATE;
  
  IF NOT FOUND THEN RAISE EXCEPTION 'APPOINTMENT_NOT_FOUND'; END IF;
  
  v_new_barber_id := COALESCE(p_new_barber_id, v_old_appointment.barber_id);
  v_new_service_id := COALESCE(p_new_service_id, v_old_appointment.service_id);

  -- 🛡️ SOVEREIGN V4.4 LOCKING: Protect the NEW Slot from Race Conditions
  -- Matches the lock acquired by create_public_appointment
  v_lock_id_1 := hashtext(v_old_appointment.barbershop_id::text);
  v_lock_id_2 := hashtext(v_new_barber_id::text || p_new_date::text || p_new_time::text);
  PERFORM pg_advisory_xact_lock(v_lock_id_1, v_lock_id_2);
  
  SELECT duration_minutes, COALESCE(padding_minutes, 0), name 
  INTO v_service_duration, v_service_padding, v_old_appointment.service_name 
  FROM services 
  WHERE id = v_new_service_id;
  
  SELECT check_appointment_conflict(v_new_barber_id, p_new_date, p_new_time, v_service_duration, v_service_padding, p_old_appointment_id) 
  INTO v_has_conflict;
  
  IF v_has_conflict THEN RAISE EXCEPTION 'SLOT_UNAVAILABLE'; END IF;
  
  UPDATE appointments SET status = 'cancelled', updated_at = NOW() WHERE id = p_old_appointment_id;
  
  INSERT INTO appointments (barbershop_id, customer_id, barber_id, service_id, appointment_date, appointment_time, notes, status, whatsapp_sent)
  VALUES (v_old_appointment.barbershop_id, v_old_appointment.customer_id, v_new_barber_id, v_new_service_id, p_new_date, p_new_time, v_old_appointment.notes, 'confirmed', false)
  RETURNING id INTO v_new_appointment_id;
  
  SELECT generate_appointment_token(v_new_appointment_id) INTO v_new_token;
  
  -- 🚀 TRANSACTIONAL OUTBOX (Sovereign V22)
  v_queue_payload := jsonb_build_object(
      'type', 'reschedule_confirmation',
      'appointmentId', v_new_appointment_id,
      'oldAppointmentId', p_old_appointment_id,
      'customerName', v_old_appointment.customer_name,
      'customerPhone', v_old_appointment.customer_phone,
      'barberName', v_old_appointment.barber_name,
      'serviceName', v_old_appointment.service_name,
      'barbershopName', v_old_appointment.barbershop_name,
      'appointmentDate', p_new_date,
      'appointmentTime', p_new_time,
      'new_token', v_new_token
  );

  INSERT INTO public.sovereign_jobs (payload) VALUES (v_queue_payload);

  RETURN json_build_object('success', TRUE, 'new_appointment_id', v_new_appointment_id, 'new_token', v_new_token);
END;
$$;


ALTER FUNCTION "public"."reschedule_appointment"("p_old_appointment_id" "uuid", "p_new_date" "date", "p_new_time" time without time zone, "p_new_barber_id" "uuid", "p_new_service_id" "uuid", "p_token" "text", "p_auth_user_id" "uuid") OWNER TO "postgres";


COMMENT ON FUNCTION "public"."reschedule_appointment"("p_old_appointment_id" "uuid", "p_new_date" "date", "p_new_time" time without time zone, "p_new_barber_id" "uuid", "p_new_service_id" "uuid", "p_token" "text", "p_auth_user_id" "uuid") IS 'Função transacional para remarcação de agendamentos. Elimina race conditions garantindo atomicidade completa.';



CREATE OR REPLACE FUNCTION "public"."rescue_stuck_jobs"() RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO ''
    AS $$
DECLARE
    rescued_count INTEGER;
    failed_count INTEGER;
BEGIN
    -- 1. Resgatar jobs que ainda têm tentativas (ex: < max_retries)
    -- [SENIOR] BACKOFF: Adiciona 2 minutos no next_retry_at para evitar "Crash Loop" imediato
    WITH rescued AS (
        UPDATE public.whatsapp_retry_queue
        SET 
            status = 'pending',
            retry_count = pg_catalog.COALESCE(retry_count, 0) + 1,
            next_retry_at = pg_catalog.NOW() + INTERVAL '2 minutes', 
            updated_at = pg_catalog.NOW(),
            error_message = '[SELF-HEAL] Recovered from stuck processing state'
        WHERE id IN (
            SELECT id FROM public.whatsapp_retry_queue
            WHERE status = 'processing' 
            AND updated_at < (pg_catalog.NOW() - INTERVAL '10 minutes')
            AND pg_catalog.COALESCE(retry_count, 0) < pg_catalog.COALESCE(max_retries, 5)
            LIMIT 1000
            FOR UPDATE SKIP LOCKED
        )
        RETURNING id
    )
    SELECT count(*) INTO rescued_count FROM rescued;

    -- 2. "Matar" jobs que excederam limite de tentativas (Poison Pills)
    WITH killed AS (
        UPDATE public.whatsapp_retry_queue
        SET 
            status = 'failed',
            error_message = '[SELF-HEAL] Max retries exceeded (Stuck Loop)',
            updated_at = pg_catalog.NOW()
        WHERE id IN (
            SELECT id FROM public.whatsapp_retry_queue
            WHERE status = 'processing' 
            AND updated_at < (pg_catalog.NOW() - INTERVAL '10 minutes')
            AND pg_catalog.COALESCE(retry_count, 0) >= pg_catalog.COALESCE(max_retries, 5)
            LIMIT 1000
            FOR UPDATE SKIP LOCKED
        )
        RETURNING id
    )
    SELECT count(*) INTO failed_count FROM killed;

    -- Logs
    IF rescued_count > 0 THEN
        RAISE NOTICE '🚑 Self-Healing: Rescued % stuck jobs.', rescued_count;
    END IF;

    IF failed_count > 0 THEN
        RAISE NOTICE '☠️ Self-Healing: Killed % poison pill jobs.', failed_count;
    END IF;
END;
$$;


ALTER FUNCTION "public"."rescue_stuck_jobs"() OWNER TO "postgres";


COMMENT ON FUNCTION "public"."rescue_stuck_jobs"() IS 'Self-healing process for WhatsApp Queue. Rescues stuck jobs and applies poison pill logic.';



CREATE OR REPLACE FUNCTION "public"."sanitize_xss_trigger"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
  v_metadata_text TEXT;
BEGIN
  -- We perform a basic check on the string representation of the JSON.
  -- This DB-level check prevents blatant script injection into logs.
  
  v_metadata_text := NEW.metadata::text;
  
  IF v_metadata_text ILIKE '%<script>%' 
  OR v_metadata_text ILIKE '%onload=%' 
  OR v_metadata_text ILIKE '%onerror=%'
  OR v_metadata_text ILIKE '%javascript:%' THEN
     -- Reject the payload entirely instead of trying to clean it dangerously
     RAISE EXCEPTION 'ERR_SECURITY_VIOLATION: XSS payload detected in audit metadata.';
  END IF;

  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."sanitize_xss_trigger"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."set_appointment_duration"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
  -- Se a duração não foi fornecida, buscar do serviço
  IF NEW.duration_minutes IS NULL THEN
    SELECT duration_minutes INTO NEW.duration_minutes
    FROM public.services
    WHERE id = NEW.service_id;
  END IF;
  
  -- Fallback seguro se serviço não for encontrado ou não tiver duração
  IF NEW.duration_minutes IS NULL THEN
     NEW.duration_minutes := 30; -- Default 30 min
  END IF;

  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."set_appointment_duration"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."set_mfa_verified_session"() RETURNS json
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
  v_aal text;
BEGIN
  -- 🛡️ STRICT SECURITY: Verify the JWT actually has the aal2 claim
  v_aal := auth.jwt() ->> 'aal';
  
  IF v_aal IS DISTINCT FROM 'aal2' THEN
    RAISE EXCEPTION 'ERR_UNAUTHORIZED: Sessão não verificada por MFA (AAL: %)', COALESCE(v_aal, 'nenhum');
  END IF;

  UPDATE auth.users
  SET raw_app_meta_data = COALESCE(raw_app_meta_data, '{}'::jsonb) || 
      jsonb_build_object(
          'mfa_verified_at', extract(epoch from now()),
          'mfa_session_id', encode(digest(auth.uid()::text || now()::text, 'sha256'), 'hex')
      )
  WHERE id = auth.uid();

  RETURN json_build_object('success', true);
END;
$$;


ALTER FUNCTION "public"."set_mfa_verified_session"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."set_time_and_duration"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'extensions'
    AS $$
begin
  if new.duration_minutes is not null and new.appointment_end_time is not null then return new; end if;
  if new.service_id is not null then
     declare v_svc_duration integer;
     begin
       select duration_minutes into v_svc_duration from public.services where id = new.service_id;
       if new.duration_minutes is null then new.duration_minutes := coalesce(v_svc_duration, 30); end if;
       if new.appointment_end_time is null then new.appointment_end_time := new.appointment_time + (new.duration_minutes || ' minutes')::interval; end if;
     end;
  else
     if new.duration_minutes is null then new.duration_minutes := 30; end if;
     if new.appointment_end_time is null then new.appointment_end_time := new.appointment_time + (30 || ' minutes')::interval; end if;
  end if;
  return new;
end;
$$;


ALTER FUNCTION "public"."set_time_and_duration"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."snapshot_appointment_details"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
DECLARE
  v_service_price DECIMAL(10,2);
  v_service_duration INTEGER;
BEGIN
  -- Se o preÃ§o jÃ¡ foi informado (ex: override manual), nÃ£o sobrescreve
  IF NEW.price IS NOT NULL AND NEW.duration_minutes IS NOT NULL THEN
    RETURN NEW;
  END IF;

  -- Buscar dados do serviÃ§o ORIGINAL no momento do agendamento
  SELECT price, duration_minutes 
  INTO v_service_price, v_service_duration
  FROM public.services
  WHERE id = NEW.service_id;

  -- Aplicar Snapshot (Copiar valor para o histÃ³rico)
  IF NEW.price IS NULL THEN
    NEW.price := COALESCE(v_service_price, 0);
  END IF;

  IF NEW.duration_minutes IS NULL THEN
    NEW.duration_minutes := COALESCE(v_service_duration, 30); -- Default safe
  END IF;

  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."snapshot_appointment_details"() OWNER TO "postgres";


COMMENT ON FUNCTION "public"."snapshot_appointment_details"() IS 'Financial Integrity: Congela o preÃ§o e duraÃ§Ã£o do serviÃ§o no momento do agendamento. Previne que futuras alteraÃ§Ãµes de preÃ§o afetem relatÃ³rios passados.';



CREATE OR REPLACE FUNCTION "public"."soft_delete_tenant"("p_barbershop_id" "uuid") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'extensions'
    AS $$
BEGIN
    -- Check if user owns the barbershop OR is a service role
    IF NOT EXISTS (
        SELECT 1 FROM public.barbershops 
        WHERE id = p_barbershop_id 
        AND (owner_id = auth.uid() OR auth.role() = 'service_role')
    ) THEN
        RAISE EXCEPTION 'UNAUTHORIZED: You do not have permission to delete this tenant.';
    END IF;

    UPDATE public.barbershops
    SET deleted_at = now(),
        subscription_status = 'cancelled'
    WHERE id = p_barbershop_id;

    -- Audit the event
    PERFORM log_sovereign_event_v2(
        'tenant.soft_delete',
        'warn',
        'Tenant marked for deletion',
        jsonb_build_object('barbershop_id', p_barbershop_id),
        auth.uid()
    );
END;
$$;


ALTER FUNCTION "public"."soft_delete_tenant"("p_barbershop_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."sovereign_cleanup_routine"() RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'extensions'
    SET "statement_timeout" TO '5min'
    AS $$
begin
  -- 1. ZOMBIE KILLER (15 minute hold for pending appointments)
  delete from public.appointments 
  where status = 'pending' 
    and created_at < (now() - interval '15 minutes');

  -- 2. LGPD Anonymization
  update public.customers
  set name = 'ANONIMIZADO',
      email = 'anon_' || id::text || '@anonimizado.com',
      phone = '00000000000'
  where id in (
    select c.id from public.customers c
    left join public.appointments a on c.id = a.customer_id
    group by c.id
    having max(a.appointment_date) < (now() - interval '5 years')
    or (max(a.appointment_date) is null and c.created_at < (now() - interval '5 years'))
  ) and email not like 'anon_%';

  -- 3. Appointment Pruning
  delete from public.appointments where appointment_date < (now() - interval '2 years');

  -- 4. Security logs
  delete from public.security_events where created_at < (now() - interval '1 year');

  -- 5. App Logs
  delete from public.whatsapp_logs where created_at < (now() - interval '90 days');
  delete from public._sovereign_audit_log where created_at < (now() - interval '90 days');
  delete from public.rate_limits where window_start < (now() - interval '1 day');
  delete from public.login_attempts where attempt_time < (now() - interval '30 days');
  delete from public.customer_magic_links where expires_at < now() or created_at < (now() - interval '24 hours');
  delete from public.whatsapp_retry_queue 
  where (status in ('completed', 'failed') and updated_at < (now() - interval '7 days'));

  insert into public._sovereign_audit_log (event, details) values ('Cleanup', 'Routine Executed (Zombie+LGPD)');

exception when others then
  insert into public._sovereign_audit_log (event, details) values ('Cleanup Error', SQLERRM);
end;
$$;


ALTER FUNCTION "public"."sovereign_cleanup_routine"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."sync_financial_from_appointments"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
BEGIN
    -- Only sync if financial fields changed
    IF (NEW.final_amount IS DISTINCT FROM OLD.final_amount) OR
       (NEW.payment_status IS DISTINCT FROM OLD.payment_status) OR
       (NEW.payment_method IS DISTINCT FROM OLD.payment_method) THEN
       
        INSERT INTO financial.transactions (
            barbershop_id, appointment_id, type, amount, method, status
        )
        VALUES (
            NEW.barbershop_id, NEW.id, 'payment', NEW.final_amount, NEW.payment_method, NEW.payment_status
        )
        ON CONFLICT (appointment_id, type) DO UPDATE SET
            amount = EXCLUDED.amount,
            method = EXCLUDED.method,
            status = EXCLUDED.status,
            updated_at = NOW();
    END IF;
    RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."sync_financial_from_appointments"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."sync_subscription_to_claims"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'auth'
    AS $$
DECLARE
  v_claims jsonb;
BEGIN
  -- 🛡️ STRICT IDENTITY: Only sync stable identifiers
  -- We removed 'plan_status' to prevent Stale State attacks.
  -- 'stripe_price_id' is kept as it changes rarely and aids limited offline logic if needed,
  -- but generally should be treated with caution.
  
  v_claims := jsonb_build_object(
    'stripe_price_id', NEW.price_id
  );

  -- Update auth.users
  UPDATE auth.users
  SET raw_app_meta_data = 
      COALESCE(raw_app_meta_data, '{}'::jsonb) || v_claims,
      -- Optional: Remove old 'plan_status' key if it exists to force cleanup
      -- using jsonb operator '-' 
      raw_app_meta_data = raw_app_meta_data - 'plan_status'
  WHERE id = NEW.user_id;

  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."sync_subscription_to_claims"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."sync_user_roles_to_app_metadata"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$
DECLARE
  v_role_data JSONB;
BEGIN
  -- Aggregate all roles/ids for the user
  SELECT jsonb_build_object(
    'role', NEW.role,
    'barber_id', (SELECT id FROM public.barbers WHERE user_id = NEW.user_id AND barbershop_id = NEW.barbershop_id LIMIT 1),
    'customer_id', (SELECT id FROM public.customers WHERE user_id = NEW.user_id AND barbershop_id = NEW.barbershop_id LIMIT 1),
    'barbershop_id', NEW.barbershop_id
  ) INTO v_role_data;

  -- 🛡️ Update auth.users.raw_app_meta_data (Server-side ONLY, immune to client manipulation)
  UPDATE auth.users
  SET raw_app_meta_data = COALESCE(raw_app_meta_data, '{}'::jsonb) || v_role_data
  WHERE id = NEW.user_id;

  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."sync_user_roles_to_app_metadata"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."track_user_event"("p_user_id" "uuid", "p_event_type" "text", "p_barbershop_id" "uuid" DEFAULT NULL::"uuid", "p_metadata" "jsonb" DEFAULT '{}'::"jsonb") RETURNS "uuid"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_event_id UUID;
BEGIN
  INSERT INTO public.user_events (user_id, barbershop_id, event_type, metadata)
  VALUES (p_user_id, p_barbershop_id, p_event_type, p_metadata)
  RETURNING id INTO v_event_id;
  
  RETURN v_event_id;
END;
$$;


ALTER FUNCTION "public"."track_user_event"("p_user_id" "uuid", "p_event_type" "text", "p_barbershop_id" "uuid", "p_metadata" "jsonb") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."trigger_calculate_commission"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
    -- Only trigger when status changes to 'completed'
    IF NEW.status = 'completed' AND (OLD.status IS DISTINCT FROM 'completed') THEN
        PERFORM calculate_commission_for_appointment(NEW.id);
    END IF;
    RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."trigger_calculate_commission"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."update_daily_metrics"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
    v_date DATE;
    v_price NUMERIC(10, 2) := 0;
    v_old_date DATE;
    v_old_price NUMERIC(10, 2) := 0;
BEGIN
    -- Handle INSERT
    IF (TG_OP = 'INSERT') THEN
        v_date := NEW.appointment_date;
        
        -- Get price if needed (Join services)
        IF NEW.status = 'completed' THEN
            SELECT price INTO v_price FROM public.services WHERE id = NEW.service_id;
        END IF;

        INSERT INTO public.daily_metrics (barbershop_id, date, appointments_count, revenue)
        VALUES (NEW.barbershop_id, v_date, 1, COALESCE(v_price, 0))
        ON CONFLICT (barbershop_id, date) DO UPDATE
        SET appointments_count = daily_metrics.appointments_count + 1,
            revenue = daily_metrics.revenue + EXCLUDED.revenue,
            updated_at = NOW();
            
    -- Handle DELETE
    ELSIF (TG_OP = 'DELETE') THEN
        v_date := OLD.appointment_date;
        
        IF OLD.status = 'completed' THEN
            SELECT price INTO v_price FROM public.services WHERE id = OLD.service_id;
        END IF;

        UPDATE public.daily_metrics
        SET appointments_count = appointments_count - 1,
            revenue = revenue - COALESCE(v_price, 0),
            updated_at = NOW()
        WHERE barbershop_id = OLD.barbershop_id AND date = v_date;

    -- Handle UPDATE
    ELSIF (TG_OP = 'UPDATE') THEN
        -- Case A: Date changed (Decrement Old, Increment New)
        IF OLD.appointment_date IS DISTINCT FROM NEW.appointment_date THEN
             -- Decrement Old
             v_old_date := OLD.appointment_date;
             IF OLD.status = 'completed' THEN
                SELECT price INTO v_old_price FROM public.services WHERE id = OLD.service_id;
             END IF;
             
             UPDATE public.daily_metrics
             SET appointments_count = appointments_count - 1,
                 revenue = revenue - COALESCE(v_old_price, 0)
             WHERE barbershop_id = OLD.barbershop_id AND date = v_old_date;

             -- Increment New
             v_date := NEW.appointment_date;
             IF NEW.status = 'completed' THEN
                SELECT price INTO v_price FROM public.services WHERE id = NEW.service_id;
             END IF;

             INSERT INTO public.daily_metrics (barbershop_id, date, appointments_count, revenue)
             VALUES (NEW.barbershop_id, v_date, 1, COALESCE(v_price, 0))
             ON CONFLICT (barbershop_id, date) DO UPDATE
             SET appointments_count = daily_metrics.appointments_count + 1,
                 revenue = daily_metrics.revenue + EXCLUDED.revenue;
                 
        -- Case B: Status changed (e.g. pending -> completed)
        ELSIF OLD.status IS DISTINCT FROM NEW.status THEN
             v_date := NEW.appointment_date;
             
             -- Revoke Old Revenue if was completed
             IF OLD.status = 'completed' THEN
                SELECT price INTO v_old_price FROM public.services WHERE id = OLD.service_id;
                UPDATE public.daily_metrics SET revenue = revenue - COALESCE(v_old_price, 0) 
                WHERE barbershop_id = NEW.barbershop_id AND date = v_date;
             END IF;
             
             -- Add New Revenue if is completed
             IF NEW.status = 'completed' THEN
                SELECT price INTO v_price FROM public.services WHERE id = NEW.service_id;
                UPDATE public.daily_metrics SET revenue = revenue + COALESCE(v_price, 0)
                WHERE barbershop_id = NEW.barbershop_id AND date = v_date;
             END IF;
        END IF;
    END IF;

    RETURN NULL;
END;
$$;


ALTER FUNCTION "public"."update_daily_metrics"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."update_subscription_overrides_updated_at"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."update_subscription_overrides_updated_at"() OWNER TO "postgres";


COMMENT ON FUNCTION "public"."update_subscription_overrides_updated_at"() IS 'Trigger function para atualizar updated_at automaticamente.
SECURITY DEFINER + search_path fixo previnem hijacking attacks.';



CREATE OR REPLACE FUNCTION "public"."update_subscription_safe"("p_barbershop_id" "uuid", "p_status" "text", "p_plan" "text", "p_ends_at" timestamp with time zone, "p_stripe_subscription_id" "text", "p_stripe_customer_id" "text", "p_event_created_at" bigint) RETURNS json
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_current_last_event bigint;
  v_updated boolean := false;
BEGIN
  -- 🔒 Row Lock (CRITICAL: Prevents race conditions)
  -- This MUST be preserved exactly as-is
  SELECT last_stripe_event_created_at INTO v_current_last_event 
  FROM public.barbershops 
  WHERE id = p_barbershop_id 
  FOR UPDATE;  -- ⚠️ CRITICAL: Do not remove or modify

  -- 🛡️ Event Ordering Check (CRITICAL: Prevents stale updates)
  -- Only process if this event is newer than the last processed event
  IF v_current_last_event IS NULL OR p_event_created_at > v_current_last_event THEN
      -- ✅ Event is newer, process it
      UPDATE public.barbershops
      SET 
        subscription_status = p_status,
        subscription_plan = p_plan,
        subscription_ends_at = p_ends_at,
        stripe_subscription_id = COALESCE(p_stripe_subscription_id, stripe_subscription_id),
        stripe_customer_id = COALESCE(p_stripe_customer_id, stripe_customer_id),
        last_stripe_event_created_at = p_event_created_at,
        updated_at = NOW()
      WHERE id = p_barbershop_id;
      
      v_updated := true;
  ELSE
      -- ⚠️ Event is older, ignore it
      -- This is expected behavior when events arrive out of order
      RAISE WARNING 'Ignored outdated Stripe event (Timestamp: %, Current: %)', 
        p_event_created_at, v_current_last_event;
  END IF;

  -- Return result indicating success and whether update occurred
  RETURN json_build_object(
    'success', true,
    'updated', v_updated,
    'ignored', NOT v_updated
  );
END;
$$;


ALTER FUNCTION "public"."update_subscription_safe"("p_barbershop_id" "uuid", "p_status" "text", "p_plan" "text", "p_ends_at" timestamp with time zone, "p_stripe_subscription_id" "text", "p_stripe_customer_id" "text", "p_event_created_at" bigint) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."update_updated_at_column"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."update_updated_at_column"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."update_whatsapp_retry_queue_updated_at"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."update_whatsapp_retry_queue_updated_at"() OWNER TO "postgres";


COMMENT ON FUNCTION "public"."update_whatsapp_retry_queue_updated_at"() IS 'Trigger function para atualizar updated_at automaticamente.
SECURITY DEFINER + search_path fixo previnem hijacking attacks.';



CREATE OR REPLACE FUNCTION "public"."validate_whatsapp_cooldown"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_last_sent_at TIMESTAMP WITH TIME ZONE;
  v_cooldown_minutes INTEGER := 5;
BEGIN
  -- Verificar se existe mensagem recente do mesmo tipo para o mesmo número
  -- Usando FOR UPDATE NOWAIT para garantir atomicidade
  BEGIN
    SELECT sent_at INTO v_last_sent_at
    FROM whatsapp_logs
    WHERE phone_number = NEW.phone_number
      AND message_type = NEW.message_type
      AND sent_at > NOW() - (v_cooldown_minutes || ' minutes')::INTERVAL
    ORDER BY sent_at DESC
    LIMIT 1
    FOR UPDATE NOWAIT;
    
    -- Se encontrou registro recente, bloquear insert
    IF v_last_sent_at IS NOT NULL THEN
      RAISE EXCEPTION 'COOLDOWN_ACTIVE: Mensagem % para % enviada há menos de % minutos (última em %)',
        NEW.message_type,
        NEW.phone_number,
        v_cooldown_minutes,
        v_last_sent_at
        USING ERRCODE = '23505'; -- Unique violation code
    END IF;
    
  EXCEPTION
    WHEN lock_not_available THEN
      -- Outra transação está processando mensagem para este número/tipo
      RAISE EXCEPTION 'COOLDOWN_LOCK: Mensagem % para % já está sendo processada',
        NEW.message_type,
        NEW.phone_number
        USING ERRCODE = '23505';
  END;
  
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."validate_whatsapp_cooldown"() OWNER TO "postgres";


COMMENT ON FUNCTION "public"."validate_whatsapp_cooldown"() IS 'Previne race conditions no cooldown WhatsApp usando SELECT FOR UPDATE NOWAIT.
Se duas requisições simultâneas tentarem enviar a mesma mensagem, a segunda
receberá um erro de lock e falhará imediatamente.';



CREATE OR REPLACE FUNCTION "public"."verify_backup_code_secure"("p_code" "text", "p_user_id" "uuid" DEFAULT NULL::"uuid", "p_ip" "inet" DEFAULT NULL::"inet") RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'pg_catalog', 'public', 'extensions', 'pg_temp'
    AS $$
DECLARE
  v_user_id UUID;
  v_record  RECORD;
  v_matched BOOLEAN := FALSE;
BEGIN
  -- Determinar user_id: da sessão ou do parâmetro (para fluxo de recovery)
  v_user_id := COALESCE(auth.uid(), p_user_id);
  IF v_user_id IS NULL THEN
    RAISE EXCEPTION 'Not authenticated' USING ERRCODE = 'P0401';
  END IF;

  -- Verificar rate-limit ANTES de qualquer operação
  PERFORM public.check_mfa_recovery_rate_limit(v_user_id, p_ip);

  -- Registrar tentativa (antes de verificar, para contar mesmo se inválido)
  INSERT INTO public.mfa_recovery_attempts (user_id, ip_address, succeeded)
  VALUES (v_user_id, p_ip, FALSE)
  RETURNING id INTO STRICT v_record;

  -- Normalizar código
  p_code := upper(trim(p_code));

  -- Verificar contra hashes armazenados (scan limitado a 10 códigos)
  FOR v_record IN
    SELECT id, code_hash
    FROM public.backup_codes
    WHERE user_id = v_user_id
      AND used_at IS NULL
      AND (expires_at IS NULL OR expires_at > NOW())
    LIMIT 10
  LOOP
    IF (v_record.code_hash = crypt(p_code, v_record.code_hash)) THEN
      -- Código válido: consumir imediatamente (single-use)
      UPDATE public.backup_codes
      SET used_at = NOW()
      WHERE id = v_record.id;

      -- Marcar tentativa como bem-sucedida
      UPDATE public.mfa_recovery_attempts
      SET succeeded = TRUE
      WHERE user_id = v_user_id
        AND attempted_at > NOW() - INTERVAL '5 seconds'
        AND succeeded = FALSE;

      v_matched := TRUE;
      EXIT;
    END IF;
  END LOOP;

  IF NOT v_matched THEN
    RETURN jsonb_build_object('valid', FALSE, 'reason', 'invalid_code');
  END IF;

  RETURN jsonb_build_object('valid', TRUE);
EXCEPTION
  WHEN SQLSTATE 'P0429' THEN
    RAISE EXCEPTION '%', SQLERRM USING ERRCODE = 'P0429';
END;
$$;


ALTER FUNCTION "public"."verify_backup_code_secure"("p_code" "text", "p_user_id" "uuid", "p_ip" "inet") OWNER TO "postgres";


COMMENT ON FUNCTION "public"."verify_backup_code_secure"("p_code" "text", "p_user_id" "uuid", "p_ip" "inet") IS '[SOVEREIGN V4.12] Rate-limited backup code verifier. Max 5 failed attempts per user per 15min. Single-use consumption on match.';



CREATE OR REPLACE FUNCTION "public"."warn_default_partition_insert"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
BEGIN
    -- Log warning (will appear in PostgreSQL logs)
    RAISE WARNING 'Log inserted into DEFAULT partition. created_at: %. Action: %. This may indicate missing partition for this date.', 
        NEW.created_at, NEW.action;
    
    -- Still allow insert (don't break functionality)
    RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."warn_default_partition_insert"() OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."appointments" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "appointment_date" "date" NOT NULL,
    "appointment_time" time without time zone NOT NULL,
    "appointment_end_time" time without time zone,
    "barbershop_id" "uuid" NOT NULL,
    "barber_id" "uuid" NOT NULL,
    "customer_id" "uuid" NOT NULL,
    "service_id" "uuid" NOT NULL,
    "status" "text" DEFAULT 'confirmed'::"text",
    "payment_status" "text" DEFAULT 'pending'::"text",
    "payment_method" "text",
    "price" numeric,
    "cost" numeric,
    "commission_rate" numeric,
    "discount_amount" numeric,
    "final_amount" numeric,
    "total_amount" numeric,
    "duration_minutes" integer,
    "notes" "text",
    "reminder_1h_sent" boolean DEFAULT false,
    "reminder_24h_sent" boolean DEFAULT false,
    "whatsapp_sent" boolean DEFAULT false
)
PARTITION BY RANGE ("appointment_date");


ALTER TABLE "public"."appointments" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."customers" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "barbershop_id" "uuid" NOT NULL,
    "name" "text" NOT NULL,
    "phone" "text" NOT NULL,
    "email" "text",
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "notes" "text",
    "user_id" "uuid",
    "is_active" boolean DEFAULT true
);


ALTER TABLE "public"."customers" OWNER TO "postgres";


COMMENT ON TABLE "public"."customers" IS 'Clientes com RLS: apenas donos da barbearia associada podem acessar dados de contato.';



CREATE TABLE IF NOT EXISTS "public"."_sovereign_audit_log" (
    "id" integer NOT NULL,
    "event" "text" NOT NULL,
    "details" "text",
    "created_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."_sovereign_audit_log" OWNER TO "postgres";


ALTER TABLE "public"."_sovereign_audit_log" ALTER COLUMN "id" ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME "public"."_sovereign_audit_log_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);



CREATE TABLE IF NOT EXISTS "public"."allowed_anon_actions" (
    "action" "text" NOT NULL,
    "description" "text" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "enabled" boolean DEFAULT true NOT NULL
);


ALTER TABLE "public"."allowed_anon_actions" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."appointment_cancellations" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "appointment_id" "uuid" NOT NULL,
    "cancelled_by" "text" NOT NULL,
    "cancelled_by_user_id" "uuid",
    "cancellation_reason" "text",
    "cancelled_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "hours_before_appointment" numeric(5,2),
    "whatsapp_sent" boolean DEFAULT false,
    "whatsapp_error" "text",
    "created_at" timestamp with time zone DEFAULT "now"(),
    CONSTRAINT "appointment_cancellations_cancelled_by_check" CHECK (("cancelled_by" = ANY (ARRAY['customer'::"text", 'barber'::"text", 'owner'::"text"])))
);


ALTER TABLE "public"."appointment_cancellations" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."appointments_legacy" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "barbershop_id" "uuid" NOT NULL,
    "barber_id" "uuid" NOT NULL,
    "service_id" "uuid" NOT NULL,
    "customer_id" "uuid" NOT NULL,
    "appointment_date" "date" NOT NULL,
    "appointment_time" time without time zone NOT NULL,
    "status" "text" DEFAULT 'pending'::"text",
    "notes" "text",
    "whatsapp_sent" boolean DEFAULT false,
    "reminder_24h_sent" boolean DEFAULT false,
    "reminder_1h_sent" boolean DEFAULT false,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "payment_method" "text",
    "payment_status" "text" DEFAULT 'pending'::"text",
    "total_amount" numeric(10,2),
    "discount_amount" numeric(10,2) DEFAULT 0,
    "final_amount" numeric(10,2),
    "appointment_end_time" time without time zone,
    "price" numeric(10,2),
    "cost" numeric(10,2),
    "commission_rate" integer,
    "duration_minutes" integer,
    CONSTRAINT "appointments_status_check" CHECK (("status" = ANY (ARRAY['pending'::"text", 'confirmed'::"text", 'completed'::"text", 'cancelled'::"text"])))
)
WITH ("autovacuum_analyze_scale_factor"='0.02', "autovacuum_vacuum_scale_factor"='0.05');


ALTER TABLE "public"."appointments_legacy" OWNER TO "postgres";


COMMENT ON TABLE "public"."appointments_legacy" IS 'Appointments com RLS: apenas donos de barbearia podem ver dados dos clientes incluindo telefones.';



CREATE OR REPLACE VIEW "public"."appointment_notifications_status" AS
 SELECT "a"."id",
    "c"."name" AS "customer_name",
    "c"."phone" AS "customer_phone",
    "a"."appointment_date",
    "a"."appointment_time",
    "a"."status",
    "a"."whatsapp_sent",
    "a"."reminder_24h_sent",
    "a"."reminder_1h_sent",
    ((("a"."appointment_date" || ' '::"text") || "a"."appointment_time"))::timestamp without time zone AS "appointment_datetime_sp",
    ("now"() AT TIME ZONE 'America/Sao_Paulo'::"text") AS "current_time_sp",
    (EXTRACT(epoch FROM (((("a"."appointment_date" || ' '::"text") || "a"."appointment_time"))::timestamp without time zone - ("now"() AT TIME ZONE 'America/Sao_Paulo'::"text"))) / (60)::numeric) AS "minutes_until_appointment",
        CASE
            WHEN ("a"."status" = 'cancelled'::"text") THEN 'cancelled'::"text"
            WHEN ("a"."whatsapp_sent" = true) THEN 'sent'::"text"
            ELSE 'pending'::"text"
        END AS "notification_status"
   FROM ("public"."appointments_legacy" "a"
     JOIN "public"."customers" "c" ON (("a"."customer_id" = "c"."id")));


ALTER VIEW "public"."appointment_notifications_status" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."appointment_tokens" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "appointment_id" "uuid" NOT NULL,
    "token" "text" NOT NULL,
    "expires_at" timestamp with time zone DEFAULT ("now"() + '30 days'::interval) NOT NULL,
    "used_at" timestamp with time zone,
    "created_at" timestamp with time zone DEFAULT "now"(),
    CONSTRAINT "ck_appointment_tokens_format" CHECK (("length"("token") = 64))
);

ALTER TABLE ONLY "public"."appointment_tokens" FORCE ROW LEVEL SECURITY;


ALTER TABLE "public"."appointment_tokens" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."appointments_default" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "appointment_date" "date" NOT NULL,
    "appointment_time" time without time zone NOT NULL,
    "appointment_end_time" time without time zone,
    "barbershop_id" "uuid" NOT NULL,
    "barber_id" "uuid" NOT NULL,
    "customer_id" "uuid" NOT NULL,
    "service_id" "uuid" NOT NULL,
    "status" "text" DEFAULT 'confirmed'::"text",
    "payment_status" "text" DEFAULT 'pending'::"text",
    "payment_method" "text",
    "price" numeric,
    "cost" numeric,
    "commission_rate" numeric,
    "discount_amount" numeric,
    "final_amount" numeric,
    "total_amount" numeric,
    "duration_minutes" integer,
    "notes" "text",
    "reminder_1h_sent" boolean DEFAULT false,
    "reminder_24h_sent" boolean DEFAULT false,
    "whatsapp_sent" boolean DEFAULT false
);


ALTER TABLE "public"."appointments_default" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."appointments_p2024" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "appointment_date" "date" NOT NULL,
    "appointment_time" time without time zone NOT NULL,
    "appointment_end_time" time without time zone,
    "barbershop_id" "uuid" NOT NULL,
    "barber_id" "uuid" NOT NULL,
    "customer_id" "uuid" NOT NULL,
    "service_id" "uuid" NOT NULL,
    "status" "text" DEFAULT 'confirmed'::"text",
    "payment_status" "text" DEFAULT 'pending'::"text",
    "payment_method" "text",
    "price" numeric,
    "cost" numeric,
    "commission_rate" numeric,
    "discount_amount" numeric,
    "final_amount" numeric,
    "total_amount" numeric,
    "duration_minutes" integer,
    "notes" "text",
    "reminder_1h_sent" boolean DEFAULT false,
    "reminder_24h_sent" boolean DEFAULT false,
    "whatsapp_sent" boolean DEFAULT false
);


ALTER TABLE "public"."appointments_p2024" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."appointments_p2025" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "appointment_date" "date" NOT NULL,
    "appointment_time" time without time zone NOT NULL,
    "appointment_end_time" time without time zone,
    "barbershop_id" "uuid" NOT NULL,
    "barber_id" "uuid" NOT NULL,
    "customer_id" "uuid" NOT NULL,
    "service_id" "uuid" NOT NULL,
    "status" "text" DEFAULT 'confirmed'::"text",
    "payment_status" "text" DEFAULT 'pending'::"text",
    "payment_method" "text",
    "price" numeric,
    "cost" numeric,
    "commission_rate" numeric,
    "discount_amount" numeric,
    "final_amount" numeric,
    "total_amount" numeric,
    "duration_minutes" integer,
    "notes" "text",
    "reminder_1h_sent" boolean DEFAULT false,
    "reminder_24h_sent" boolean DEFAULT false,
    "whatsapp_sent" boolean DEFAULT false
);


ALTER TABLE "public"."appointments_p2025" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."appointments_p2026" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "appointment_date" "date" NOT NULL,
    "appointment_time" time without time zone NOT NULL,
    "appointment_end_time" time without time zone,
    "barbershop_id" "uuid" NOT NULL,
    "barber_id" "uuid" NOT NULL,
    "customer_id" "uuid" NOT NULL,
    "service_id" "uuid" NOT NULL,
    "status" "text" DEFAULT 'confirmed'::"text",
    "payment_status" "text" DEFAULT 'pending'::"text",
    "payment_method" "text",
    "price" numeric,
    "cost" numeric,
    "commission_rate" numeric,
    "discount_amount" numeric,
    "final_amount" numeric,
    "total_amount" numeric,
    "duration_minutes" integer,
    "notes" "text",
    "reminder_1h_sent" boolean DEFAULT false,
    "reminder_24h_sent" boolean DEFAULT false,
    "whatsapp_sent" boolean DEFAULT false
);


ALTER TABLE "public"."appointments_p2026" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_action_registry" (
    "action" "text" NOT NULL,
    "description" "text" NOT NULL,
    "category" "text" NOT NULL,
    "severity" "text" NOT NULL,
    "enabled" boolean DEFAULT true NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "audit_action_registry_severity_check" CHECK (("severity" = ANY (ARRAY['info'::"text", 'warning'::"text", 'critical'::"text"])))
);


ALTER TABLE "public"."audit_action_registry" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
)
PARTITION BY RANGE ("created_at");


ALTER TABLE "public"."audit_logs" OWNER TO "postgres";


COMMENT ON TABLE "public"."audit_logs" IS 'Sovereign Audit Log (Phase 4.1 Cleaned). RPC V1 and Tracking Views removed.';



CREATE TABLE IF NOT EXISTS "public"."audit_logs_2026_01" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
);


ALTER TABLE "public"."audit_logs_2026_01" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs_2026_02" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
);


ALTER TABLE "public"."audit_logs_2026_02" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs_2026_03" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
);


ALTER TABLE "public"."audit_logs_2026_03" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs_2026_04" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
);


ALTER TABLE "public"."audit_logs_2026_04" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs_2026_05" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
);


ALTER TABLE "public"."audit_logs_2026_05" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs_2026_06" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
);


ALTER TABLE "public"."audit_logs_2026_06" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs_2026_07" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
);


ALTER TABLE "public"."audit_logs_2026_07" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs_2026_08" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
);


ALTER TABLE "public"."audit_logs_2026_08" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs_2026_09" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
);


ALTER TABLE "public"."audit_logs_2026_09" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs_2026_10" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
);


ALTER TABLE "public"."audit_logs_2026_10" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs_2026_11" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
);


ALTER TABLE "public"."audit_logs_2026_11" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs_2026_12" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
);


ALTER TABLE "public"."audit_logs_2026_12" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs_2027_01" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
);


ALTER TABLE "public"."audit_logs_2027_01" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs_2027_02" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
);


ALTER TABLE "public"."audit_logs_2027_02" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs_2027_03" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
);


ALTER TABLE "public"."audit_logs_2027_03" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs_2027_04" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
);


ALTER TABLE "public"."audit_logs_2027_04" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs_2027_05" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
);


ALTER TABLE "public"."audit_logs_2027_05" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs_2027_06" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
);


ALTER TABLE "public"."audit_logs_2027_06" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs_2027_07" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
);


ALTER TABLE "public"."audit_logs_2027_07" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs_2027_08" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
);


ALTER TABLE "public"."audit_logs_2027_08" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs_2027_09" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
);


ALTER TABLE "public"."audit_logs_2027_09" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs_2027_10" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
);


ALTER TABLE "public"."audit_logs_2027_10" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs_2027_11" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
);


ALTER TABLE "public"."audit_logs_2027_11" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs_2027_12" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
);


ALTER TABLE "public"."audit_logs_2027_12" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs_2028_01" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
);


ALTER TABLE "public"."audit_logs_2028_01" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs_2028_02" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
);


ALTER TABLE "public"."audit_logs_2028_02" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs_2028_03" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
);


ALTER TABLE "public"."audit_logs_2028_03" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs_2028_04" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
);


ALTER TABLE "public"."audit_logs_2028_04" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs_2028_05" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
);


ALTER TABLE "public"."audit_logs_2028_05" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs_2028_06" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
);


ALTER TABLE "public"."audit_logs_2028_06" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs_2028_07" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
);


ALTER TABLE "public"."audit_logs_2028_07" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs_2028_08" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
);


ALTER TABLE "public"."audit_logs_2028_08" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs_2028_09" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
);


ALTER TABLE "public"."audit_logs_2028_09" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs_2028_10" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
);


ALTER TABLE "public"."audit_logs_2028_10" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs_2028_11" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
);


ALTER TABLE "public"."audit_logs_2028_11" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs_2028_12" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
);


ALTER TABLE "public"."audit_logs_2028_12" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_logs_default" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "action" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "public"."ip_address",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "description" "text",
    "session_id" "text",
    "level" "public"."audit_level" DEFAULT 'info'::"public"."audit_level" NOT NULL,
    CONSTRAINT "check_created_at_not_ancient" CHECK (("created_at" >= '2020-01-01 00:00:00'::timestamp without time zone)),
    CONSTRAINT "check_created_at_not_future" CHECK (("created_at" <= ("now"() + '1 day'::interval))),
    CONSTRAINT "check_metadata_is_object" CHECK (("jsonb_typeof"("metadata") = 'object'::"text"))
);


ALTER TABLE "public"."audit_logs_default" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."auth_otps" (
    "phone" "text" NOT NULL,
    "code_hash" "text" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "expires_at" timestamp with time zone NOT NULL,
    "attempts" integer DEFAULT 0,
    "lockout_until" timestamp with time zone
);


ALTER TABLE "public"."auth_otps" OWNER TO "postgres";


COMMENT ON TABLE "public"."auth_otps" IS 'Armazena códigos OTP hash para autenticação via WhatsApp';



CREATE TABLE IF NOT EXISTS "public"."backup_codes" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid" NOT NULL,
    "code_hash" "text" NOT NULL,
    "used_at" timestamp with time zone,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "expires_at" timestamp with time zone DEFAULT ("now"() + '1 year'::interval)
);


ALTER TABLE "public"."backup_codes" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."barbers" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "barbershop_id" "uuid" NOT NULL,
    "name" "text" NOT NULL,
    "avatar_url" "text",
    "phone" "text",
    "working_hours" "jsonb" DEFAULT '{"friday": {"end": "18:00", "start": "09:00"}, "monday": {"end": "18:00", "start": "09:00"}, "sunday": null, "tuesday": {"end": "18:00", "start": "09:00"}, "saturday": {"end": "14:00", "start": "09:00"}, "thursday": {"end": "18:00", "start": "09:00"}, "wednesday": {"end": "18:00", "start": "09:00"}}'::"jsonb",
    "is_active" boolean DEFAULT true,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "commission_percentage" numeric(5,2) DEFAULT 40.00,
    "user_id" "uuid",
    "commission_rate" integer DEFAULT 50,
    CONSTRAINT "barbers_commission_rate_check" CHECK ((("commission_rate" >= 0) AND ("commission_rate" <= 100)))
);


ALTER TABLE "public"."barbers" OWNER TO "postgres";


COMMENT ON COLUMN "public"."barbers"."phone" IS 'Telefone PESSOAL do barbeiro - NUNCA deve ser exposto publicamente. Apenas owners podem ver.';



CREATE TABLE IF NOT EXISTS "public"."barbershop_expenses" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "barbershop_id" "uuid" NOT NULL,
    "description" "text" NOT NULL,
    "amount" numeric(10,2) NOT NULL,
    "date" "date" DEFAULT CURRENT_DATE NOT NULL,
    "category" "text" DEFAULT 'General'::"text",
    "recurrence" "public"."expense_recurrence" DEFAULT 'one_off'::"public"."expense_recurrence",
    "created_at" timestamp with time zone DEFAULT "now"(),
    "created_by" "uuid",
    CONSTRAINT "barbershop_expenses_amount_check" CHECK (("amount" > (0)::numeric))
);


ALTER TABLE "public"."barbershop_expenses" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."barbershops" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "owner_id" "uuid" NOT NULL,
    "name" "text" NOT NULL,
    "slug" "text" NOT NULL,
    "description" "text",
    "logo_url" "text",
    "phone" "text",
    "address" "text",
    "primary_color" "text" DEFAULT '#FFD700'::"text",
    "secondary_color" "text" DEFAULT '#000000'::"text",
    "loyalty_enabled" boolean DEFAULT false,
    "loyalty_points_per_service" integer DEFAULT 1,
    "loyalty_points_for_reward" integer DEFAULT 10,
    "loyalty_reward_service" "text",
    "subscription_plan" "text" DEFAULT 'free'::"text",
    "subscription_status" "text" DEFAULT 'trial'::"text",
    "trial_ends_at" timestamp with time zone DEFAULT ("now"() + '3 days'::interval),
    "subscription_ends_at" timestamp with time zone,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "subscription_started_at" timestamp with time zone,
    "stripe_subscription_id" "text",
    "stripe_customer_id" "text",
    "megaapi_instance_key" "text",
    "megaapi_token" "text",
    "megaapi_host" "text" DEFAULT 'apistart02.megaapi.com.br'::"text",
    "is_active" boolean DEFAULT true,
    "deleted_at" timestamp with time zone,
    "last_stripe_event_created_at" bigint,
    "opening_time" time without time zone DEFAULT '09:00:00'::time without time zone NOT NULL,
    "closing_time" time without time zone DEFAULT '18:00:00'::time without time zone NOT NULL,
    CONSTRAINT "barbershops_subscription_plan_check" CHECK (("subscription_plan" = ANY (ARRAY['free'::"text", 'professional'::"text", 'premium'::"text"]))),
    CONSTRAINT "barbershops_subscription_status_check" CHECK (("subscription_status" = ANY (ARRAY['trial'::"text", 'active'::"text", 'cancelled'::"text", 'expired'::"text"])))
);


ALTER TABLE "public"."barbershops" OWNER TO "postgres";


COMMENT ON COLUMN "public"."barbershops"."owner_id" IS 'ID do proprietário - NUNCA deve ser exposto publicamente. Apenas o próprio owner pode ver.';



COMMENT ON COLUMN "public"."barbershops"."phone" IS 'Telefone comercial da barbearia - atualmente público para permitir contato de clientes.';



COMMENT ON COLUMN "public"."barbershops"."subscription_plan" IS 'Plano de assinatura - informação comercial sensível. Apenas o owner pode ver.';



COMMENT ON COLUMN "public"."barbershops"."trial_ends_at" IS 'Data de fim do trial - informação comercial sensível. Apenas o owner pode ver.';



COMMENT ON COLUMN "public"."barbershops"."subscription_ends_at" IS 'Data de fim da assinatura - informação comercial sensível. Apenas o owner pode ver.';



COMMENT ON COLUMN "public"."barbershops"."is_active" IS 'Emergency Fix: Restored missing column used by core booking RPCs.';



COMMENT ON COLUMN "public"."barbershops"."opening_time" IS 'Horário de abertura padrão da barbearia';



COMMENT ON COLUMN "public"."barbershops"."closing_time" IS 'Horário de fechamento padrão da barbearia';



CREATE TABLE IF NOT EXISTS "public"."bi_log" (
    "id" bigint NOT NULL,
    "tenant_id" "uuid" NOT NULL,
    "metric_date" "date" DEFAULT CURRENT_DATE NOT NULL,
    "metric_type" "text" NOT NULL,
    "metric_value" numeric DEFAULT 0 NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "bi_log_metric_type_check" CHECK (("metric_type" = ANY (ARRAY['appointment_count'::"text", 'revenue'::"text"])))
);


ALTER TABLE "public"."bi_log" OWNER TO "postgres";


ALTER TABLE "public"."bi_log" ALTER COLUMN "id" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "public"."bi_log_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);



CREATE TABLE IF NOT EXISTS "public"."blacklisted_ips" (
    "ip_address" "inet" NOT NULL,
    "reason" "text",
    "banned_at" timestamp with time zone DEFAULT "now"(),
    "expires_at" timestamp with time zone
);


ALTER TABLE "public"."blacklisted_ips" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."cancel_reasons" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "reason_text" "text" NOT NULL,
    "is_active" boolean DEFAULT true,
    "created_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."cancel_reasons" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."commission_settings" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "barbershop_id" "uuid" NOT NULL,
    "barber_id" "uuid",
    "service_id" "uuid",
    "percentage" numeric(5,2),
    "fixed_amount" numeric(10,2),
    "rule_type" "public"."commission_rule_type" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    CONSTRAINT "commission_settings_fixed_amount_check" CHECK (("fixed_amount" >= (0)::numeric)),
    CONSTRAINT "commission_settings_percentage_check" CHECK ((("percentage" >= (0)::numeric) AND ("percentage" <= (100)::numeric))),
    CONSTRAINT "enforce_rule_logic" CHECK (((("rule_type" = 'global'::"public"."commission_rule_type") AND ("barber_id" IS NULL) AND ("service_id" IS NULL)) OR (("rule_type" = 'barber_specific'::"public"."commission_rule_type") AND ("barber_id" IS NOT NULL)) OR (("rule_type" = 'service_specific'::"public"."commission_rule_type") AND ("service_id" IS NOT NULL))))
);


ALTER TABLE "public"."commission_settings" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."commissions" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "barbershop_id" "uuid" NOT NULL,
    "barber_id" "uuid" NOT NULL,
    "sale_id" "uuid",
    "appointment_id" "uuid",
    "service_amount" numeric(10,2) DEFAULT 0,
    "product_amount" numeric(10,2) DEFAULT 0,
    "commission_percentage" numeric(5,2) NOT NULL,
    "commission_amount" numeric(10,2) NOT NULL,
    "is_paid" boolean DEFAULT false NOT NULL,
    "paid_at" timestamp with time zone,
    "reference_date" "date" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."commissions" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."cron_health_logs" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "job_name" "text" NOT NULL,
    "execution_time" timestamp with time zone DEFAULT "now"(),
    "status" "text" NOT NULL,
    "details" "jsonb",
    "created_at" timestamp with time zone DEFAULT "now"(),
    CONSTRAINT "cron_health_logs_status_check" CHECK (("status" = ANY (ARRAY['running'::"text", 'success'::"text", 'failed'::"text", 'partial'::"text"])))
);


ALTER TABLE "public"."cron_health_logs" OWNER TO "postgres";


COMMENT ON TABLE "public"."cron_health_logs" IS 'Logs de execução dos CRON jobs para monitoramento';



CREATE TABLE IF NOT EXISTS "public"."csp_violations" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "barbershop_id" "uuid",
    "blocked_uri" "text" NOT NULL,
    "violated_directive" "text" NOT NULL,
    "effective_directive" "text",
    "original_policy" "text",
    "source_file" "text",
    "line_number" integer,
    "column_number" integer,
    "document_uri" "text" NOT NULL,
    "referrer" "text",
    "disposition" "text",
    "user_agent" "text",
    "ip_address" "inet",
    "script_sample" "text",
    "status_code" integer,
    "violated_at" timestamp with time zone NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "occurrence_count" integer DEFAULT 1
);


ALTER TABLE "public"."csp_violations" OWNER TO "postgres";


COMMENT ON TABLE "public"."csp_violations" IS 'Armazena violações de Content Security Policy para monitoramento de segurança';



COMMENT ON COLUMN "public"."csp_violations"."blocked_uri" IS 'URI do recurso que foi bloqueado pela CSP';



COMMENT ON COLUMN "public"."csp_violations"."violated_directive" IS 'Diretiva CSP que foi violada (ex: script-src, img-src)';



COMMENT ON COLUMN "public"."csp_violations"."occurrence_count" IS 'Número de vezes que esta violação específica ocorreu';



CREATE TABLE IF NOT EXISTS "public"."customer_magic_links" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "customer_id" "uuid",
    "token" "text" NOT NULL,
    "expires_at" timestamp with time zone DEFAULT ("now"() + '01:00:00'::interval),
    "created_at" timestamp with time zone DEFAULT "now"(),
    "used_at" timestamp with time zone
);


ALTER TABLE "public"."customer_magic_links" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."daily_metrics" (
    "barbershop_id" "uuid" NOT NULL,
    "date" "date" NOT NULL,
    "appointments_count" integer DEFAULT 0,
    "revenue" numeric(10,2) DEFAULT 0,
    "updated_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."daily_metrics" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."data_retention_audit_log" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "operation_type" "text" NOT NULL,
    "records_anonymized" integer DEFAULT 0,
    "executed_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."data_retention_audit_log" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."data_retention_log" (
    "id" "uuid" DEFAULT "extensions"."uuid_generate_v4"() NOT NULL,
    "operation" "text" NOT NULL,
    "records_affected" integer,
    "executed_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."data_retention_log" OWNER TO "postgres";


COMMENT ON TABLE "public"."data_retention_log" IS 'Log de execuções da política de retenção de dados (LGPD)';



CREATE TABLE IF NOT EXISTS "public"."expenses" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "barbershop_id" "uuid" NOT NULL,
    "description" "text" NOT NULL,
    "amount" numeric(10,2) NOT NULL,
    "category" "text",
    "expense_date" "date" DEFAULT CURRENT_DATE,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."expenses" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."financial_ledger" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "barbershop_id" "uuid" NOT NULL,
    "appointment_id" "uuid",
    "appointment_date" "date",
    "barber_id" "uuid",
    "transaction_type" "public"."transaction_type" NOT NULL,
    "amount" numeric(10,2) NOT NULL,
    "description" "text",
    "status" "public"."transaction_status" DEFAULT 'pending'::"public"."transaction_status" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."financial_ledger" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."login_attempts" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "email" "text" NOT NULL,
    "ip_address" "text",
    "success" boolean DEFAULT false NOT NULL,
    "attempted_at" timestamp with time zone DEFAULT "now"(),
    "attempt_time" timestamp with time zone DEFAULT "now"()
)
WITH ("autovacuum_vacuum_scale_factor"='0.05');


ALTER TABLE "public"."login_attempts" OWNER TO "postgres";


COMMENT ON TABLE "public"."login_attempts" IS 'Log de tentativas de login para proteção contra Brute Force';



CREATE TABLE IF NOT EXISTS "public"."loyalty_points" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "barbershop_id" "uuid" NOT NULL,
    "customer_id" "uuid" NOT NULL,
    "points" integer DEFAULT 0,
    "total_earned" integer DEFAULT 0,
    "rewards_redeemed" integer DEFAULT 0,
    "last_updated" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."loyalty_points" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."mfa_recovery_attempts" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid" NOT NULL,
    "attempted_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "ip_address" "inet",
    "succeeded" boolean DEFAULT false NOT NULL
);


ALTER TABLE "public"."mfa_recovery_attempts" OWNER TO "postgres";


COMMENT ON TABLE "public"."mfa_recovery_attempts" IS '[SOVEREIGN V4.12] Rate-limit log for backup code verification attempts. Prevents brute-force against MFA recovery codes.';



CREATE OR REPLACE VIEW "public"."mfa_recovery_audit" AS
 SELECT "user_id",
    "ip_address",
    "attempted_at",
    "succeeded",
    "date_trunc"('hour'::"text", "attempted_at") AS "hour_bucket"
   FROM "public"."mfa_recovery_attempts"
  ORDER BY "attempted_at" DESC;


ALTER VIEW "public"."mfa_recovery_audit" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."notification_queue" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "appointment_id" "uuid",
    "type" "text" DEFAULT 'confirmation'::"text" NOT NULL,
    "status" "text" DEFAULT 'pending'::"text",
    "payload" "jsonb" NOT NULL,
    "attempts" integer DEFAULT 0,
    "max_attempts" integer DEFAULT 5,
    "next_retry_at" timestamp with time zone DEFAULT "now"(),
    "last_error" "text",
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    CONSTRAINT "notification_queue_status_check" CHECK (("status" = ANY (ARRAY['pending'::"text", 'processing'::"text", 'completed'::"text", 'failed'::"text"])))
);


ALTER TABLE "public"."notification_queue" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."security_events" (
    "id" "uuid" DEFAULT "extensions"."uuid_generate_v4"() NOT NULL,
    "type" "text" NOT NULL,
    "severity" "text" NOT NULL,
    "user_id" "uuid",
    "ip_address" "text",
    "user_agent" "text",
    "details" "jsonb",
    "alerted" boolean DEFAULT false,
    "created_at" timestamp with time zone DEFAULT "now"(),
    CONSTRAINT "security_events_severity_check" CHECK (("severity" = ANY (ARRAY['critical'::"text", 'high'::"text", 'medium'::"text", 'low'::"text"]))),
    CONSTRAINT "security_events_type_check" CHECK (("type" = ANY (ARRAY['login_failure'::"text", 'permission_change'::"text", 'data_access'::"text", 'sql_injection'::"text", 'rate_limit'::"text", 'error'::"text", 'suspicious_activity'::"text"])))
);


ALTER TABLE "public"."security_events" OWNER TO "postgres";


COMMENT ON TABLE "public"."security_events" IS 'Eventos de segurança para sistema de alertas (MON-003)';



CREATE OR REPLACE VIEW "public"."pending_security_alerts" AS
 SELECT "id",
    "type",
    "severity",
    "user_id",
    "ip_address",
    "details",
    "created_at"
   FROM "public"."security_events"
  WHERE (("alerted" = false) AND ("severity" = ANY (ARRAY['critical'::"text", 'high'::"text"])) AND ("created_at" > ("now"() - '24:00:00'::interval)))
  ORDER BY
        CASE "severity"
            WHEN 'critical'::"text" THEN 1
            WHEN 'high'::"text" THEN 2
            ELSE NULL::integer
        END, "created_at" DESC;


ALTER VIEW "public"."pending_security_alerts" OWNER TO "postgres";


COMMENT ON VIEW "public"."pending_security_alerts" IS 'Eventos críticos/altos pendentes de alerta';



CREATE TABLE IF NOT EXISTS "public"."permission_audit_log" (
    "id" "uuid" DEFAULT "extensions"."uuid_generate_v4"() NOT NULL,
    "user_id" "uuid" NOT NULL,
    "target_user_id" "uuid",
    "action" "text" NOT NULL,
    "resource" "text" NOT NULL,
    "old_value" "jsonb",
    "new_value" "jsonb",
    "ip_address" "text",
    "user_agent" "text",
    "created_at" timestamp with time zone DEFAULT "now"(),
    CONSTRAINT "permission_audit_log_action_check" CHECK (("action" = ANY (ARRAY['grant_role'::"text", 'revoke_role'::"text", 'update_permissions'::"text", 'create_user'::"text", 'delete_user'::"text"])))
);

ALTER TABLE ONLY "public"."permission_audit_log" FORCE ROW LEVEL SECURITY;


ALTER TABLE "public"."permission_audit_log" OWNER TO "postgres";


COMMENT ON TABLE "public"."permission_audit_log" IS 'Auditoria de mudanças de permissões. Retenção: 1 ano.';



CREATE TABLE IF NOT EXISTS "public"."plans" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "name" "text" NOT NULL,
    "label" "text" NOT NULL,
    "description" "text",
    "provider_id" "text" NOT NULL,
    "provider_product_id" "text",
    "price_brl" numeric(10,2) NOT NULL,
    "features" "jsonb" DEFAULT '[]'::"jsonb",
    "is_active" boolean DEFAULT true,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."plans" OWNER TO "postgres";


COMMENT ON TABLE "public"."plans" IS 'Source of Truth para Preços e Planos. Desacopla o Frontend do Vendor (Stripe).';



COMMENT ON COLUMN "public"."plans"."provider_id" IS 'ID do Preço no Gateway de Pagamento (ex: Stripe Price ID).';



CREATE TABLE IF NOT EXISTS "public"."products" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "barbershop_id" "uuid" NOT NULL,
    "name" "text" NOT NULL,
    "barcode" "text",
    "cost_price" numeric(10,2) DEFAULT 0 NOT NULL,
    "sale_price" numeric(10,2) NOT NULL,
    "stock_quantity" integer DEFAULT 0 NOT NULL,
    "is_active" boolean DEFAULT true NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."products" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."profiles" (
    "id" "uuid" NOT NULL,
    "full_name" "text",
    "email" "text",
    "phone" "text",
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "role" "text" DEFAULT 'customer'::"text"
);


ALTER TABLE "public"."profiles" OWNER TO "postgres";


COMMENT ON TABLE "public"."profiles" IS 'Public user profile information';



CREATE OR REPLACE VIEW "public"."public_barbers" AS
 SELECT "id",
    "barbershop_id",
    "name",
    "avatar_url",
    "working_hours",
    "is_active",
    ( SELECT "barbershops"."slug"
           FROM "public"."barbershops"
          WHERE ("barbershops"."id" = "barbers"."barbershop_id")) AS "barbershop_slug"
   FROM "public"."barbers";


ALTER VIEW "public"."public_barbers" OWNER TO "postgres";


CREATE OR REPLACE VIEW "public"."public_barbers_secure" AS
 SELECT "id",
    "barbershop_id",
    "name",
    "avatar_url",
    "working_hours",
    "is_active",
    ( SELECT "barbershops"."slug"
           FROM "public"."barbershops"
          WHERE ("barbershops"."id" = "barbers"."barbershop_id")) AS "barbershop_slug"
   FROM "public"."barbers";


ALTER VIEW "public"."public_barbers_secure" OWNER TO "postgres";


CREATE OR REPLACE VIEW "public"."public_barbers_ultra_safe" AS
 SELECT "id",
    "name",
    "avatar_url",
    "is_active",
    "barbershop_id"
   FROM "public"."barbers" "b"
  WHERE ("is_active" = true);


ALTER VIEW "public"."public_barbers_ultra_safe" OWNER TO "postgres";


CREATE OR REPLACE VIEW "public"."public_barbershops" AS
 SELECT "id",
    "name",
    "slug",
    "logo_url",
    "primary_color",
    "secondary_color",
    "description",
    "subscription_status"
   FROM "public"."barbershops";


ALTER VIEW "public"."public_barbershops" OWNER TO "postgres";


CREATE OR REPLACE VIEW "public"."public_barbershops_complete" AS
 SELECT "id",
    "name",
    "slug",
    "description",
    "logo_url",
    "primary_color",
    "secondary_color",
    "subscription_plan",
    "subscription_status",
    "trial_ends_at"
   FROM "public"."barbershops";


ALTER VIEW "public"."public_barbershops_complete" OWNER TO "postgres";


CREATE OR REPLACE VIEW "public"."public_barbershops_safe" AS
 SELECT "id",
    "name",
    "slug",
    "logo_url",
    "primary_color",
    "secondary_color",
    "description",
    "subscription_status",
    "subscription_plan",
    "trial_ends_at",
    "loyalty_enabled",
    "loyalty_points_per_service",
    "loyalty_points_for_reward",
    "loyalty_reward_service"
   FROM "public"."barbershops";


ALTER VIEW "public"."public_barbershops_safe" OWNER TO "postgres";


CREATE OR REPLACE VIEW "public"."public_barbershops_ultra_safe" AS
 SELECT "id",
    "name",
    "slug",
    "description",
    "address",
    "phone",
    "primary_color",
    "secondary_color",
    "logo_url"
   FROM "public"."barbershops";


ALTER VIEW "public"."public_barbershops_ultra_safe" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."services" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "barbershop_id" "uuid" NOT NULL,
    "name" "text" NOT NULL,
    "description" "text",
    "price" numeric(10,2) NOT NULL,
    "duration_minutes" integer DEFAULT 30 NOT NULL,
    "is_active" boolean DEFAULT true,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "commission_percentage" numeric(5,2),
    "cost" numeric(10,2) DEFAULT 0.00,
    "padding_minutes" integer DEFAULT 0,
    CONSTRAINT "services_duration_check" CHECK (("duration_minutes" > 0)),
    CONSTRAINT "services_price_check" CHECK (("price" >= (0)::numeric))
);


ALTER TABLE "public"."services" OWNER TO "postgres";


CREATE OR REPLACE VIEW "public"."public_services" AS
 SELECT "id",
    "barbershop_id",
    "name",
    "description",
    "price",
    "duration_minutes",
    ( SELECT "barbershops"."slug"
           FROM "public"."barbershops"
          WHERE ("barbershops"."id" = "services"."barbershop_id")) AS "barbershop_slug"
   FROM "public"."services";


ALTER VIEW "public"."public_services" OWNER TO "postgres";


CREATE OR REPLACE VIEW "public"."public_services_safe" AS
 SELECT "id",
    "name",
    "description",
    "price",
    "duration_minutes",
    "barbershop_id",
    "is_active"
   FROM "public"."services" "s"
  WHERE ("is_active" = true);


ALTER VIEW "public"."public_services_safe" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."rate_limits" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "identifier" "text" NOT NULL,
    "function_name" "text" NOT NULL,
    "count" integer DEFAULT 1,
    "window_start" timestamp with time zone DEFAULT "now"(),
    "created_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."rate_limits" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."salary_expenses" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "barbershop_id" "uuid",
    "barber_id" "uuid",
    "amount" numeric(10,2) NOT NULL,
    "reference_month" "date" NOT NULL,
    "paid_at" timestamp with time zone,
    "status" "text" DEFAULT 'pending'::"text",
    "created_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."salary_expenses" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."sale_items" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "sale_id" "uuid" NOT NULL,
    "product_id" "uuid",
    "product_name" "text" NOT NULL,
    "quantity" integer NOT NULL,
    "unit_price" numeric(10,2) NOT NULL,
    "total_price" numeric(10,2) NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."sale_items" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."sales" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "barbershop_id" "uuid" NOT NULL,
    "appointment_id" "uuid",
    "customer_id" "uuid",
    "barber_id" "uuid",
    "total_amount" numeric(10,2) NOT NULL,
    "discount_amount" numeric(10,2) DEFAULT 0,
    "final_amount" numeric(10,2) NOT NULL,
    "payment_method" "text" NOT NULL,
    "payment_status" "text" DEFAULT 'paid'::"text" NOT NULL,
    "sale_date" timestamp with time zone DEFAULT "now"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."sales" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."sovereign_audit_events" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"(),
    "event_type" "text" NOT NULL,
    "severity" "text" DEFAULT 'info'::"text" NOT NULL,
    "function_name" "text",
    "details" "jsonb" DEFAULT '{}'::"jsonb",
    "user_id" "uuid",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb"
);

ALTER TABLE ONLY "public"."sovereign_audit_events" FORCE ROW LEVEL SECURITY;


ALTER TABLE "public"."sovereign_audit_events" OWNER TO "postgres";


COMMENT ON TABLE "public"."sovereign_audit_events" IS 'VUL-011 REMEDIADO (2025): Tabela APPEND-ONLY. INSERT somente via service_role. DELETE e UPDATE bloqueados via RLS para todos os usuários autenticados e anon.';



CREATE TABLE IF NOT EXISTS "public"."subscription_logs" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "barbershop_id" "uuid" NOT NULL,
    "event_type" "text" NOT NULL,
    "old_status" "text",
    "new_status" "text",
    "old_plan" "text",
    "new_plan" "text",
    "stripe_subscription_id" "text",
    "stripe_event_id" "text",
    "payment_timestamp" timestamp with time zone,
    "subscription_start" timestamp with time zone,
    "subscription_end" timestamp with time zone,
    "metadata" "jsonb",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."subscription_logs" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."subscription_overrides" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid" NOT NULL,
    "plan" "text" NOT NULL,
    "active" boolean DEFAULT true NOT NULL,
    "notes" "text",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "subscription_overrides_plan_check" CHECK (("plan" = ANY (ARRAY['free'::"text", 'professional'::"text", 'premium'::"text"])))
);


ALTER TABLE "public"."subscription_overrides" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."subscriptions" (
    "id" "text" NOT NULL,
    "user_id" "uuid" NOT NULL,
    "status" "text",
    "metadata" "jsonb",
    "price_id" "text",
    "quantity" integer,
    "cancel_at_period_end" boolean,
    "created_at" timestamp with time zone DEFAULT "timezone"('utc'::"text", "now"()) NOT NULL,
    "current_period_start" timestamp with time zone DEFAULT "timezone"('utc'::"text", "now"()) NOT NULL,
    "current_period_end" timestamp with time zone DEFAULT "timezone"('utc'::"text", "now"()) NOT NULL,
    "ended_at" timestamp with time zone,
    "cancel_at" timestamp with time zone,
    "canceled_at" timestamp with time zone,
    "trial_start" timestamp with time zone,
    "trial_end" timestamp with time zone,
    CONSTRAINT "subscriptions_status_check" CHECK (("status" = ANY (ARRAY['trialing'::"text", 'active'::"text", 'canceled'::"text", 'incomplete'::"text", 'incomplete_expired'::"text", 'past_due'::"text", 'unpaid'::"text", 'paused'::"text"])))
);


ALTER TABLE "public"."subscriptions" OWNER TO "postgres";


COMMENT ON TABLE "public"."subscriptions" IS 'Mirror of Stripe Subscriptions (Created during Migration Recovery)';



CREATE OR REPLACE VIEW "public"."suspicious_permission_changes" AS
 SELECT "pal"."id",
    "pal"."user_id",
    "pal"."target_user_id",
    "pal"."action",
    "pal"."resource",
    "pal"."old_value",
    "pal"."new_value",
    "pal"."ip_address",
    "pal"."user_agent",
    "pal"."created_at",
    "u1"."email" AS "changed_by_email",
    "u2"."email" AS "target_email"
   FROM (("public"."permission_audit_log" "pal"
     LEFT JOIN "auth"."users" "u1" ON (("pal"."user_id" = "u1"."id")))
     LEFT JOIN "auth"."users" "u2" ON (("pal"."target_user_id" = "u2"."id")))
  WHERE ((("pal"."new_value" ->> 'role'::"text") = 'admin'::"text") OR (( SELECT "count"(*) AS "count"
           FROM "public"."permission_audit_log" "pal2"
          WHERE (("pal2"."user_id" = "pal"."user_id") AND ("pal2"."created_at" > ("now"() - '01:00:00'::interval)))) > 5))
  ORDER BY "pal"."created_at" DESC;


ALTER VIEW "public"."suspicious_permission_changes" OWNER TO "postgres";


CREATE OR REPLACE VIEW "public"."system_health_monitor" AS
 SELECT "current_database"() AS "db_name",
    "version"() AS "pg_version",
    "pg_postmaster_start_time"() AS "last_restart",
    ( SELECT "count"(*) AS "count"
           FROM "pg_stat_activity") AS "active_connections",
    ( SELECT "pg_size_pretty"("pg_database_size"("current_database"())) AS "pg_size_pretty") AS "db_size";


ALTER VIEW "public"."system_health_monitor" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."system_settings" (
    "key" "text" NOT NULL,
    "value" "jsonb" NOT NULL,
    "description" "text",
    "updated_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."system_settings" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."user_events" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid" NOT NULL,
    "barbershop_id" "uuid",
    "event_type" "text" NOT NULL,
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."user_events" OWNER TO "postgres";


COMMENT ON COLUMN "public"."user_events"."event_type" IS 'Tipos válidos: signup_completed, first_barber_added, first_service_added, first_customer_added, first_appointment_created, first_appointment_completed, trial_started, trial_ending_soon, trial_expired, subscription_started, subscription_cancelled';



CREATE TABLE IF NOT EXISTS "public"."user_roles" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid" NOT NULL,
    "barbershop_id" "uuid",
    "role" "public"."app_role" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."user_roles" OWNER TO "postgres";


COMMENT ON TABLE "public"."user_roles" IS 'RBAC Roles for users';



CREATE TABLE IF NOT EXISTS "public"."user_security_profiles" (
    "user_id" "uuid" NOT NULL,
    "mfa_enabled" boolean DEFAULT false NOT NULL,
    "totp_secret" "text",
    "recovery_codes" "text"[],
    "updated_at" timestamp with time zone DEFAULT "now"(),
    "created_at" timestamp with time zone DEFAULT "now"()
);


ALTER TABLE "public"."user_security_profiles" OWNER TO "postgres";


CREATE OR REPLACE VIEW "public"."v_audit_logs_health" AS
 SELECT "schemaname",
    "relname" AS "tablename",
    "pg_size_pretty"("pg_total_relation_size"((((("schemaname")::"text" || '.'::"text") || ("relname")::"text"))::"regclass")) AS "size",
    "pg_total_relation_size"((((("schemaname")::"text" || '.'::"text") || ("relname")::"text"))::"regclass") AS "size_bytes",
    "n_tup_ins" AS "total_inserts",
    "n_tup_upd" AS "total_updates",
    "n_tup_del" AS "total_deletes",
    "n_live_tup" AS "live_rows",
    "last_vacuum",
    "last_autovacuum"
   FROM "pg_stat_user_tables"
  WHERE ("relname" ~~ 'audit_logs%'::"text")
  ORDER BY ("pg_total_relation_size"((((("schemaname")::"text" || '.'::"text") || ("relname")::"text"))::"regclass")) DESC;


ALTER VIEW "public"."v_audit_logs_health" OWNER TO "postgres";


CREATE OR REPLACE VIEW "public"."v_sovereign_alerts" AS
 SELECT "id",
    "created_at",
    "action",
    "level",
    "user_id",
    "ip_address",
    "description",
    "metadata"
   FROM "public"."audit_logs"
  WHERE (("level" = 'critical'::"public"."audit_level") OR ("action" = ANY (ARRAY['zombie_write_blocked'::"text", 'rate_limit_exceeded'::"text", 'unauthorized_access'::"text", 'privilege_escalation_attempt'::"text"])))
  ORDER BY "created_at" DESC;


ALTER VIEW "public"."v_sovereign_alerts" OWNER TO "postgres";


CREATE OR REPLACE VIEW "public"."view_daily_metrics_unified" AS
 SELECT COALESCE("m"."barbershop_id", "l"."tenant_id") AS "barbershop_id",
    COALESCE("m"."date", "l"."metric_date") AS "date",
    ((COALESCE("m"."appointments_count", 0))::numeric + COALESCE("l"."pending_appointments", (0)::numeric)) AS "total_appointments",
    (COALESCE("m"."revenue", (0)::numeric) + COALESCE("l"."pending_revenue", (0)::numeric)) AS "total_revenue"
   FROM ("public"."daily_metrics" "m"
     FULL JOIN ( SELECT "bi_log"."tenant_id",
            "bi_log"."metric_date",
            "sum"(
                CASE
                    WHEN ("bi_log"."metric_type" = 'appointment_count'::"text") THEN "bi_log"."metric_value"
                    ELSE (0)::numeric
                END) AS "pending_appointments",
            "sum"(
                CASE
                    WHEN ("bi_log"."metric_type" = 'revenue'::"text") THEN "bi_log"."metric_value"
                    ELSE (0)::numeric
                END) AS "pending_revenue"
           FROM "public"."bi_log"
          GROUP BY "bi_log"."tenant_id", "bi_log"."metric_date") "l" ON ((("m"."barbershop_id" = "l"."tenant_id") AND ("m"."date" = "l"."metric_date"))));


ALTER VIEW "public"."view_daily_metrics_unified" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."whatsapp_logs" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "appointment_id" "uuid",
    "barbershop_id" "uuid" NOT NULL,
    "message_type" "text" NOT NULL,
    "phone_number" "text" NOT NULL,
    "status" "text" NOT NULL,
    "twilio_sid" "text",
    "error_message" "text",
    "sent_at" timestamp with time zone DEFAULT "now"(),
    "created_at" timestamp with time zone DEFAULT "now"(),
    "megaapi_message_id" "text",
    "template_name" "text",
    "idempotency_key" "uuid"
);


ALTER TABLE "public"."whatsapp_logs" OWNER TO "postgres";


COMMENT ON TABLE "public"."whatsapp_logs" IS 'Logs de WhatsApp são IMUTÁVEIS. INSERT apenas via service_role (edge functions). UPDATE e DELETE bloqueados para todos os usuários.';



COMMENT ON COLUMN "public"."whatsapp_logs"."megaapi_message_id" IS 'ID único da mensagem retornado pela API MegaAPI após envio bem-sucedido';



CREATE TABLE IF NOT EXISTS "public"."whatsapp_retry_queue" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "appointment_id" "uuid" NOT NULL,
    "message_type" "text" NOT NULL,
    "phone_number" "text" NOT NULL,
    "template_data" "jsonb" NOT NULL,
    "retry_count" integer DEFAULT 0,
    "max_retries" integer DEFAULT 3,
    "next_retry_at" timestamp with time zone,
    "status" "text" DEFAULT 'pending'::"text",
    "error_message" "text",
    "created_at" timestamp with time zone DEFAULT "now"(),
    "updated_at" timestamp with time zone DEFAULT "now"(),
    CONSTRAINT "whatsapp_retry_queue_status_check" CHECK (("status" = ANY (ARRAY['pending'::"text", 'processing'::"text", 'completed'::"text", 'failed'::"text"])))
)
WITH ("autovacuum_vacuum_scale_factor"='0.0', "autovacuum_vacuum_threshold"='100', "autovacuum_analyze_scale_factor"='0.0', "autovacuum_analyze_threshold"='200');


ALTER TABLE "public"."whatsapp_retry_queue" OWNER TO "postgres";


ALTER TABLE ONLY "public"."appointments" ATTACH PARTITION "public"."appointments_default" DEFAULT;



ALTER TABLE ONLY "public"."appointments" ATTACH PARTITION "public"."appointments_p2024" FOR VALUES FROM ('2024-01-01') TO ('2025-01-01');



ALTER TABLE ONLY "public"."appointments" ATTACH PARTITION "public"."appointments_p2025" FOR VALUES FROM ('2025-01-01') TO ('2026-01-01');



ALTER TABLE ONLY "public"."appointments" ATTACH PARTITION "public"."appointments_p2026" FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');



ALTER TABLE ONLY "public"."audit_logs" ATTACH PARTITION "public"."audit_logs_2026_01" FOR VALUES FROM ('2026-01-01 00:00:00+00') TO ('2026-02-01 00:00:00+00');



ALTER TABLE ONLY "public"."audit_logs" ATTACH PARTITION "public"."audit_logs_2026_02" FOR VALUES FROM ('2026-02-01 00:00:00+00') TO ('2026-03-01 00:00:00+00');



ALTER TABLE ONLY "public"."audit_logs" ATTACH PARTITION "public"."audit_logs_2026_03" FOR VALUES FROM ('2026-03-01 00:00:00+00') TO ('2026-04-01 00:00:00+00');



ALTER TABLE ONLY "public"."audit_logs" ATTACH PARTITION "public"."audit_logs_2026_04" FOR VALUES FROM ('2026-04-01 00:00:00+00') TO ('2026-05-01 00:00:00+00');



ALTER TABLE ONLY "public"."audit_logs" ATTACH PARTITION "public"."audit_logs_2026_05" FOR VALUES FROM ('2026-05-01 00:00:00+00') TO ('2026-06-01 00:00:00+00');



ALTER TABLE ONLY "public"."audit_logs" ATTACH PARTITION "public"."audit_logs_2026_06" FOR VALUES FROM ('2026-06-01 00:00:00+00') TO ('2026-07-01 00:00:00+00');



ALTER TABLE ONLY "public"."audit_logs" ATTACH PARTITION "public"."audit_logs_2026_07" FOR VALUES FROM ('2026-07-01 00:00:00+00') TO ('2026-08-01 00:00:00+00');



ALTER TABLE ONLY "public"."audit_logs" ATTACH PARTITION "public"."audit_logs_2026_08" FOR VALUES FROM ('2026-08-01 00:00:00+00') TO ('2026-09-01 00:00:00+00');



ALTER TABLE ONLY "public"."audit_logs" ATTACH PARTITION "public"."audit_logs_2026_09" FOR VALUES FROM ('2026-09-01 00:00:00+00') TO ('2026-10-01 00:00:00+00');



ALTER TABLE ONLY "public"."audit_logs" ATTACH PARTITION "public"."audit_logs_2026_10" FOR VALUES FROM ('2026-10-01 00:00:00+00') TO ('2026-11-01 00:00:00+00');



ALTER TABLE ONLY "public"."audit_logs" ATTACH PARTITION "public"."audit_logs_2026_11" FOR VALUES FROM ('2026-11-01 00:00:00+00') TO ('2026-12-01 00:00:00+00');



ALTER TABLE ONLY "public"."audit_logs" ATTACH PARTITION "public"."audit_logs_2026_12" FOR VALUES FROM ('2026-12-01 00:00:00+00') TO ('2027-01-01 00:00:00+00');



ALTER TABLE ONLY "public"."audit_logs" ATTACH PARTITION "public"."audit_logs_2027_01" FOR VALUES FROM ('2027-01-01 00:00:00+00') TO ('2027-02-01 00:00:00+00');



ALTER TABLE ONLY "public"."audit_logs" ATTACH PARTITION "public"."audit_logs_2027_02" FOR VALUES FROM ('2027-02-01 00:00:00+00') TO ('2027-03-01 00:00:00+00');



ALTER TABLE ONLY "public"."audit_logs" ATTACH PARTITION "public"."audit_logs_2027_03" FOR VALUES FROM ('2027-03-01 00:00:00+00') TO ('2027-04-01 00:00:00+00');



ALTER TABLE ONLY "public"."audit_logs" ATTACH PARTITION "public"."audit_logs_2027_04" FOR VALUES FROM ('2027-04-01 00:00:00+00') TO ('2027-05-01 00:00:00+00');



ALTER TABLE ONLY "public"."audit_logs" ATTACH PARTITION "public"."audit_logs_2027_05" FOR VALUES FROM ('2027-05-01 00:00:00+00') TO ('2027-06-01 00:00:00+00');



ALTER TABLE ONLY "public"."audit_logs" ATTACH PARTITION "public"."audit_logs_2027_06" FOR VALUES FROM ('2027-06-01 00:00:00+00') TO ('2027-07-01 00:00:00+00');



ALTER TABLE ONLY "public"."audit_logs" ATTACH PARTITION "public"."audit_logs_2027_07" FOR VALUES FROM ('2027-07-01 00:00:00+00') TO ('2027-08-01 00:00:00+00');



ALTER TABLE ONLY "public"."audit_logs" ATTACH PARTITION "public"."audit_logs_2027_08" FOR VALUES FROM ('2027-08-01 00:00:00+00') TO ('2027-09-01 00:00:00+00');



ALTER TABLE ONLY "public"."audit_logs" ATTACH PARTITION "public"."audit_logs_2027_09" FOR VALUES FROM ('2027-09-01 00:00:00+00') TO ('2027-10-01 00:00:00+00');



ALTER TABLE ONLY "public"."audit_logs" ATTACH PARTITION "public"."audit_logs_2027_10" FOR VALUES FROM ('2027-10-01 00:00:00+00') TO ('2027-11-01 00:00:00+00');



ALTER TABLE ONLY "public"."audit_logs" ATTACH PARTITION "public"."audit_logs_2027_11" FOR VALUES FROM ('2027-11-01 00:00:00+00') TO ('2027-12-01 00:00:00+00');



ALTER TABLE ONLY "public"."audit_logs" ATTACH PARTITION "public"."audit_logs_2027_12" FOR VALUES FROM ('2027-12-01 00:00:00+00') TO ('2028-01-01 00:00:00+00');



ALTER TABLE ONLY "public"."audit_logs" ATTACH PARTITION "public"."audit_logs_2028_01" FOR VALUES FROM ('2028-01-01 00:00:00+00') TO ('2028-02-01 00:00:00+00');



ALTER TABLE ONLY "public"."audit_logs" ATTACH PARTITION "public"."audit_logs_2028_02" FOR VALUES FROM ('2028-02-01 00:00:00+00') TO ('2028-03-01 00:00:00+00');



ALTER TABLE ONLY "public"."audit_logs" ATTACH PARTITION "public"."audit_logs_2028_03" FOR VALUES FROM ('2028-03-01 00:00:00+00') TO ('2028-04-01 00:00:00+00');



ALTER TABLE ONLY "public"."audit_logs" ATTACH PARTITION "public"."audit_logs_2028_04" FOR VALUES FROM ('2028-04-01 00:00:00+00') TO ('2028-05-01 00:00:00+00');



ALTER TABLE ONLY "public"."audit_logs" ATTACH PARTITION "public"."audit_logs_2028_05" FOR VALUES FROM ('2028-05-01 00:00:00+00') TO ('2028-06-01 00:00:00+00');



ALTER TABLE ONLY "public"."audit_logs" ATTACH PARTITION "public"."audit_logs_2028_06" FOR VALUES FROM ('2028-06-01 00:00:00+00') TO ('2028-07-01 00:00:00+00');



ALTER TABLE ONLY "public"."audit_logs" ATTACH PARTITION "public"."audit_logs_2028_07" FOR VALUES FROM ('2028-07-01 00:00:00+00') TO ('2028-08-01 00:00:00+00');



ALTER TABLE ONLY "public"."audit_logs" ATTACH PARTITION "public"."audit_logs_2028_08" FOR VALUES FROM ('2028-08-01 00:00:00+00') TO ('2028-09-01 00:00:00+00');



ALTER TABLE ONLY "public"."audit_logs" ATTACH PARTITION "public"."audit_logs_2028_09" FOR VALUES FROM ('2028-09-01 00:00:00+00') TO ('2028-10-01 00:00:00+00');



ALTER TABLE ONLY "public"."audit_logs" ATTACH PARTITION "public"."audit_logs_2028_10" FOR VALUES FROM ('2028-10-01 00:00:00+00') TO ('2028-11-01 00:00:00+00');



ALTER TABLE ONLY "public"."audit_logs" ATTACH PARTITION "public"."audit_logs_2028_11" FOR VALUES FROM ('2028-11-01 00:00:00+00') TO ('2028-12-01 00:00:00+00');



ALTER TABLE ONLY "public"."audit_logs" ATTACH PARTITION "public"."audit_logs_2028_12" FOR VALUES FROM ('2028-12-01 00:00:00+00') TO ('2029-01-01 00:00:00+00');



ALTER TABLE ONLY "public"."audit_logs" ATTACH PARTITION "public"."audit_logs_default" DEFAULT;



ALTER TABLE ONLY "public"."_sovereign_audit_log"
    ADD CONSTRAINT "_sovereign_audit_log_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."allowed_anon_actions"
    ADD CONSTRAINT "allowed_anon_actions_pkey" PRIMARY KEY ("action");



ALTER TABLE ONLY "public"."appointment_cancellations"
    ADD CONSTRAINT "appointment_cancellations_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."appointment_tokens"
    ADD CONSTRAINT "appointment_tokens_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."appointments"
    ADD CONSTRAINT "appointments_pkey1" PRIMARY KEY ("id", "appointment_date");



ALTER TABLE ONLY "public"."appointments_default"
    ADD CONSTRAINT "appointments_default_pkey" PRIMARY KEY ("id", "appointment_date");



ALTER TABLE ONLY "public"."appointments_p2024"
    ADD CONSTRAINT "appointments_p2024_pkey" PRIMARY KEY ("id", "appointment_date");



ALTER TABLE ONLY "public"."appointments_p2025"
    ADD CONSTRAINT "appointments_p2025_pkey" PRIMARY KEY ("id", "appointment_date");



ALTER TABLE ONLY "public"."appointments_p2026"
    ADD CONSTRAINT "appointments_p2026_pkey" PRIMARY KEY ("id", "appointment_date");



ALTER TABLE ONLY "public"."appointments_legacy"
    ADD CONSTRAINT "appointments_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."audit_action_registry"
    ADD CONSTRAINT "audit_action_registry_pkey" PRIMARY KEY ("action");



ALTER TABLE ONLY "public"."audit_logs"
    ADD CONSTRAINT "audit_logs_pkey1" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."audit_logs_2026_01"
    ADD CONSTRAINT "audit_logs_2026_01_pkey" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."audit_logs_2026_02"
    ADD CONSTRAINT "audit_logs_2026_02_pkey" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."audit_logs_2026_03"
    ADD CONSTRAINT "audit_logs_2026_03_pkey" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."audit_logs_2026_04"
    ADD CONSTRAINT "audit_logs_2026_04_pkey" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."audit_logs_2026_05"
    ADD CONSTRAINT "audit_logs_2026_05_pkey" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."audit_logs_2026_06"
    ADD CONSTRAINT "audit_logs_2026_06_pkey" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."audit_logs_2026_07"
    ADD CONSTRAINT "audit_logs_2026_07_pkey" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."audit_logs_2026_08"
    ADD CONSTRAINT "audit_logs_2026_08_pkey" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."audit_logs_2026_09"
    ADD CONSTRAINT "audit_logs_2026_09_pkey" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."audit_logs_2026_10"
    ADD CONSTRAINT "audit_logs_2026_10_pkey" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."audit_logs_2026_11"
    ADD CONSTRAINT "audit_logs_2026_11_pkey" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."audit_logs_2026_12"
    ADD CONSTRAINT "audit_logs_2026_12_pkey" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."audit_logs_2027_01"
    ADD CONSTRAINT "audit_logs_2027_01_pkey" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."audit_logs_2027_02"
    ADD CONSTRAINT "audit_logs_2027_02_pkey" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."audit_logs_2027_03"
    ADD CONSTRAINT "audit_logs_2027_03_pkey" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."audit_logs_2027_04"
    ADD CONSTRAINT "audit_logs_2027_04_pkey" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."audit_logs_2027_05"
    ADD CONSTRAINT "audit_logs_2027_05_pkey" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."audit_logs_2027_06"
    ADD CONSTRAINT "audit_logs_2027_06_pkey" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."audit_logs_2027_07"
    ADD CONSTRAINT "audit_logs_2027_07_pkey" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."audit_logs_2027_08"
    ADD CONSTRAINT "audit_logs_2027_08_pkey" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."audit_logs_2027_09"
    ADD CONSTRAINT "audit_logs_2027_09_pkey" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."audit_logs_2027_10"
    ADD CONSTRAINT "audit_logs_2027_10_pkey" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."audit_logs_2027_11"
    ADD CONSTRAINT "audit_logs_2027_11_pkey" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."audit_logs_2027_12"
    ADD CONSTRAINT "audit_logs_2027_12_pkey" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."audit_logs_2028_01"
    ADD CONSTRAINT "audit_logs_2028_01_pkey" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."audit_logs_2028_02"
    ADD CONSTRAINT "audit_logs_2028_02_pkey" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."audit_logs_2028_03"
    ADD CONSTRAINT "audit_logs_2028_03_pkey" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."audit_logs_2028_04"
    ADD CONSTRAINT "audit_logs_2028_04_pkey" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."audit_logs_2028_05"
    ADD CONSTRAINT "audit_logs_2028_05_pkey" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."audit_logs_2028_06"
    ADD CONSTRAINT "audit_logs_2028_06_pkey" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."audit_logs_2028_07"
    ADD CONSTRAINT "audit_logs_2028_07_pkey" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."audit_logs_2028_08"
    ADD CONSTRAINT "audit_logs_2028_08_pkey" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."audit_logs_2028_09"
    ADD CONSTRAINT "audit_logs_2028_09_pkey" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."audit_logs_2028_10"
    ADD CONSTRAINT "audit_logs_2028_10_pkey" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."audit_logs_2028_11"
    ADD CONSTRAINT "audit_logs_2028_11_pkey" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."audit_logs_2028_12"
    ADD CONSTRAINT "audit_logs_2028_12_pkey" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."audit_logs_default"
    ADD CONSTRAINT "audit_logs_default_pkey" PRIMARY KEY ("created_at", "id");



ALTER TABLE ONLY "public"."auth_otps"
    ADD CONSTRAINT "auth_otps_pkey" PRIMARY KEY ("phone");



ALTER TABLE ONLY "public"."backup_codes"
    ADD CONSTRAINT "backup_codes_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."barbers"
    ADD CONSTRAINT "barbers_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."barbershop_expenses"
    ADD CONSTRAINT "barbershop_expenses_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."barbershops"
    ADD CONSTRAINT "barbershops_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."barbershops"
    ADD CONSTRAINT "barbershops_slug_key" UNIQUE ("slug");



ALTER TABLE ONLY "public"."bi_log"
    ADD CONSTRAINT "bi_log_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."blacklisted_ips"
    ADD CONSTRAINT "blacklisted_ips_pkey" PRIMARY KEY ("ip_address");



ALTER TABLE ONLY "public"."cancel_reasons"
    ADD CONSTRAINT "cancel_reasons_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."commission_settings"
    ADD CONSTRAINT "commission_settings_barbershop_id_rule_type_barber_id_servi_key" UNIQUE ("barbershop_id", "rule_type", "barber_id", "service_id");



ALTER TABLE ONLY "public"."commission_settings"
    ADD CONSTRAINT "commission_settings_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."commissions"
    ADD CONSTRAINT "commissions_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."cron_health_logs"
    ADD CONSTRAINT "cron_health_logs_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."csp_violations"
    ADD CONSTRAINT "csp_violations_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."customer_magic_links"
    ADD CONSTRAINT "customer_magic_links_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."customers"
    ADD CONSTRAINT "customers_barbershop_id_phone_key" UNIQUE ("barbershop_id", "phone");



ALTER TABLE ONLY "public"."customers"
    ADD CONSTRAINT "customers_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."daily_metrics"
    ADD CONSTRAINT "daily_metrics_pkey" PRIMARY KEY ("barbershop_id", "date");



ALTER TABLE ONLY "public"."data_retention_audit_log"
    ADD CONSTRAINT "data_retention_audit_log_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."data_retention_log"
    ADD CONSTRAINT "data_retention_log_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."expenses"
    ADD CONSTRAINT "expenses_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."financial_ledger"
    ADD CONSTRAINT "financial_ledger_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."login_attempts"
    ADD CONSTRAINT "login_attempts_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."loyalty_points"
    ADD CONSTRAINT "loyalty_points_barbershop_id_customer_id_key" UNIQUE ("barbershop_id", "customer_id");



ALTER TABLE ONLY "public"."loyalty_points"
    ADD CONSTRAINT "loyalty_points_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."mfa_recovery_attempts"
    ADD CONSTRAINT "mfa_recovery_attempts_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."appointments_legacy"
    ADD CONSTRAINT "no_double_booking_overlap" EXCLUDE USING "gist" ("barber_id" WITH =, "tsrange"(("appointment_date" + "appointment_time"), (("appointment_date" + "appointment_time") + (("duration_minutes")::double precision * '00:01:00'::interval)), '[)'::"text") WITH &&) WHERE (("status" <> 'cancelled'::"text"));



COMMENT ON CONSTRAINT "no_double_booking_overlap" ON "public"."appointments_legacy" IS 'Impede agendamentos sobrepostos para o mesmo barbeiro (Race Condition Protection).';



ALTER TABLE ONLY "public"."notification_queue"
    ADD CONSTRAINT "notification_queue_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."permission_audit_log"
    ADD CONSTRAINT "permission_audit_log_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."plans"
    ADD CONSTRAINT "plans_name_key" UNIQUE ("name");



ALTER TABLE ONLY "public"."plans"
    ADD CONSTRAINT "plans_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."products"
    ADD CONSTRAINT "products_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."profiles"
    ADD CONSTRAINT "profiles_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."rate_limits"
    ADD CONSTRAINT "rate_limits_identifier_func_key" UNIQUE ("identifier", "function_name");



ALTER TABLE ONLY "public"."rate_limits"
    ADD CONSTRAINT "rate_limits_identifier_function_name_window_start_key" UNIQUE ("identifier", "function_name", "window_start");



ALTER TABLE ONLY "public"."rate_limits"
    ADD CONSTRAINT "rate_limits_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."salary_expenses"
    ADD CONSTRAINT "salary_expenses_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."sale_items"
    ADD CONSTRAINT "sale_items_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."sales"
    ADD CONSTRAINT "sales_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."security_events"
    ADD CONSTRAINT "security_events_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."services"
    ADD CONSTRAINT "services_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."sovereign_audit_events"
    ADD CONSTRAINT "sovereign_audit_events_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."subscription_logs"
    ADD CONSTRAINT "subscription_logs_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."subscription_overrides"
    ADD CONSTRAINT "subscription_overrides_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."subscription_overrides"
    ADD CONSTRAINT "subscription_overrides_user_id_key" UNIQUE ("user_id");



ALTER TABLE ONLY "public"."subscriptions"
    ADD CONSTRAINT "subscriptions_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."system_settings"
    ADD CONSTRAINT "system_settings_pkey" PRIMARY KEY ("key");



ALTER TABLE ONLY "public"."appointment_tokens"
    ADD CONSTRAINT "uk_appointment_tokens_appointment_id" UNIQUE ("appointment_id");



ALTER TABLE ONLY "public"."appointment_tokens"
    ADD CONSTRAINT "uk_appointment_tokens_token" UNIQUE ("token");



ALTER TABLE ONLY "public"."customers"
    ADD CONSTRAINT "uk_customers_phone_barbershop" UNIQUE ("barbershop_id", "phone");



ALTER TABLE ONLY "public"."appointments_legacy"
    ADD CONSTRAINT "unique_active_appointment_slot" UNIQUE ("barbershop_id", "barber_id", "appointment_date", "appointment_time");



ALTER TABLE ONLY "public"."sales"
    ADD CONSTRAINT "unique_appointment_sale" UNIQUE ("appointment_id");



COMMENT ON CONSTRAINT "unique_appointment_sale" ON "public"."sales" IS 'Previne processamento duplicado de checkout para o mesmo agendamento (idempotência).';



ALTER TABLE ONLY "public"."customers"
    ADD CONSTRAINT "unique_customer_per_shop" UNIQUE ("barbershop_id", "phone");



ALTER TABLE ONLY "public"."user_events"
    ADD CONSTRAINT "user_events_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."user_roles"
    ADD CONSTRAINT "user_roles_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."user_roles"
    ADD CONSTRAINT "user_roles_user_id_barbershop_id_role_key" UNIQUE ("user_id", "barbershop_id", "role");



ALTER TABLE ONLY "public"."user_security_profiles"
    ADD CONSTRAINT "user_security_profiles_pkey" PRIMARY KEY ("user_id");



ALTER TABLE ONLY "public"."webhook_events"
    ADD CONSTRAINT "webhook_events_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."whatsapp_logs"
    ADD CONSTRAINT "whatsapp_logs_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."whatsapp_retry_queue"
    ADD CONSTRAINT "whatsapp_retry_queue_pkey" PRIMARY KEY ("id");



CREATE INDEX "idx_appointments_v5_date" ON ONLY "public"."appointments" USING "btree" ("appointment_date");



CREATE INDEX "appointments_default_appointment_date_idx" ON "public"."appointments_default" USING "btree" ("appointment_date");



CREATE INDEX "idx_appointments_retention" ON ONLY "public"."appointments" USING "btree" ("appointment_date");



CREATE INDEX "appointments_default_appointment_date_idx1" ON "public"."appointments_default" USING "btree" ("appointment_date");



CREATE UNIQUE INDEX "idx_unique_active_slot" ON ONLY "public"."appointments" USING "btree" ("barber_id", "appointment_date", "appointment_time") WHERE ("status" <> 'cancelled'::"text");



CREATE UNIQUE INDEX "appointments_default_barber_id_appointment_date_appointment_idx" ON "public"."appointments_default" USING "btree" ("barber_id", "appointment_date", "appointment_time") WHERE ("status" <> 'cancelled'::"text");



CREATE INDEX "idx_appointments_v5_barber_date" ON ONLY "public"."appointments" USING "btree" ("barber_id", "appointment_date");



CREATE INDEX "appointments_default_barber_id_appointment_date_idx" ON "public"."appointments_default" USING "btree" ("barber_id", "appointment_date");



CREATE INDEX "idx_appointments_bs_date" ON ONLY "public"."appointments" USING "btree" ("barbershop_id", "appointment_date");



CREATE INDEX "appointments_default_barbershop_id_appointment_date_idx" ON "public"."appointments_default" USING "btree" ("barbershop_id", "appointment_date");



CREATE INDEX "idx_appointments_v5_barbershop" ON ONLY "public"."appointments" USING "btree" ("barbershop_id");



CREATE INDEX "appointments_default_barbershop_id_idx" ON "public"."appointments_default" USING "btree" ("barbershop_id");



CREATE INDEX "idx_appointments_v5_created_at" ON ONLY "public"."appointments" USING "btree" ("created_at");



CREATE INDEX "appointments_default_created_at_idx" ON "public"."appointments_default" USING "btree" ("created_at");



CREATE INDEX "idx_appointments_v5_customer" ON ONLY "public"."appointments" USING "btree" ("customer_id");



CREATE INDEX "appointments_default_customer_id_idx" ON "public"."appointments_default" USING "btree" ("customer_id");



CREATE INDEX "idx_appointments_v5_status" ON ONLY "public"."appointments" USING "btree" ("status");



CREATE INDEX "appointments_default_status_idx" ON "public"."appointments_default" USING "btree" ("status");



CREATE INDEX "appointments_p2024_appointment_date_idx" ON "public"."appointments_p2024" USING "btree" ("appointment_date");



CREATE INDEX "appointments_p2024_appointment_date_idx1" ON "public"."appointments_p2024" USING "btree" ("appointment_date");



CREATE UNIQUE INDEX "appointments_p2024_barber_id_appointment_date_appointment_t_idx" ON "public"."appointments_p2024" USING "btree" ("barber_id", "appointment_date", "appointment_time") WHERE ("status" <> 'cancelled'::"text");



CREATE INDEX "appointments_p2024_barber_id_appointment_date_idx" ON "public"."appointments_p2024" USING "btree" ("barber_id", "appointment_date");



CREATE INDEX "appointments_p2024_barbershop_id_appointment_date_idx" ON "public"."appointments_p2024" USING "btree" ("barbershop_id", "appointment_date");



CREATE INDEX "appointments_p2024_barbershop_id_idx" ON "public"."appointments_p2024" USING "btree" ("barbershop_id");



CREATE INDEX "appointments_p2024_created_at_idx" ON "public"."appointments_p2024" USING "btree" ("created_at");



CREATE INDEX "appointments_p2024_customer_id_idx" ON "public"."appointments_p2024" USING "btree" ("customer_id");



CREATE INDEX "appointments_p2024_status_idx" ON "public"."appointments_p2024" USING "btree" ("status");



CREATE INDEX "appointments_p2025_appointment_date_idx" ON "public"."appointments_p2025" USING "btree" ("appointment_date");



CREATE INDEX "appointments_p2025_appointment_date_idx1" ON "public"."appointments_p2025" USING "btree" ("appointment_date");



CREATE UNIQUE INDEX "appointments_p2025_barber_id_appointment_date_appointment_t_idx" ON "public"."appointments_p2025" USING "btree" ("barber_id", "appointment_date", "appointment_time") WHERE ("status" <> 'cancelled'::"text");



CREATE INDEX "appointments_p2025_barber_id_appointment_date_idx" ON "public"."appointments_p2025" USING "btree" ("barber_id", "appointment_date");



CREATE INDEX "appointments_p2025_barbershop_id_appointment_date_idx" ON "public"."appointments_p2025" USING "btree" ("barbershop_id", "appointment_date");



CREATE INDEX "appointments_p2025_barbershop_id_idx" ON "public"."appointments_p2025" USING "btree" ("barbershop_id");



CREATE INDEX "appointments_p2025_created_at_idx" ON "public"."appointments_p2025" USING "btree" ("created_at");



CREATE INDEX "appointments_p2025_customer_id_idx" ON "public"."appointments_p2025" USING "btree" ("customer_id");



CREATE INDEX "appointments_p2025_status_idx" ON "public"."appointments_p2025" USING "btree" ("status");



CREATE INDEX "appointments_p2026_appointment_date_idx" ON "public"."appointments_p2026" USING "btree" ("appointment_date");



CREATE INDEX "appointments_p2026_appointment_date_idx1" ON "public"."appointments_p2026" USING "btree" ("appointment_date");



CREATE UNIQUE INDEX "appointments_p2026_barber_id_appointment_date_appointment_t_idx" ON "public"."appointments_p2026" USING "btree" ("barber_id", "appointment_date", "appointment_time") WHERE ("status" <> 'cancelled'::"text");



CREATE INDEX "appointments_p2026_barber_id_appointment_date_idx" ON "public"."appointments_p2026" USING "btree" ("barber_id", "appointment_date");



CREATE INDEX "appointments_p2026_barbershop_id_appointment_date_idx" ON "public"."appointments_p2026" USING "btree" ("barbershop_id", "appointment_date");



CREATE INDEX "appointments_p2026_barbershop_id_idx" ON "public"."appointments_p2026" USING "btree" ("barbershop_id");



CREATE INDEX "appointments_p2026_created_at_idx" ON "public"."appointments_p2026" USING "btree" ("created_at");



CREATE INDEX "appointments_p2026_customer_id_idx" ON "public"."appointments_p2026" USING "btree" ("customer_id");



CREATE INDEX "appointments_p2026_status_idx" ON "public"."appointments_p2026" USING "btree" ("status");



CREATE INDEX "idx_audit_logs_action" ON ONLY "public"."audit_logs" USING "btree" ("action");



CREATE INDEX "audit_logs_2026_01_action_idx" ON "public"."audit_logs_2026_01" USING "btree" ("action");



CREATE INDEX "idx_audit_logs_session_id" ON ONLY "public"."audit_logs" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "audit_logs_2026_01_session_id_idx" ON "public"."audit_logs_2026_01" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "idx_audit_logs_user_id" ON ONLY "public"."audit_logs" USING "btree" ("user_id");



CREATE INDEX "audit_logs_2026_01_user_id_idx" ON "public"."audit_logs_2026_01" USING "btree" ("user_id");



CREATE INDEX "audit_logs_2026_02_action_idx" ON "public"."audit_logs_2026_02" USING "btree" ("action");



CREATE INDEX "audit_logs_2026_02_session_id_idx" ON "public"."audit_logs_2026_02" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "audit_logs_2026_02_user_id_idx" ON "public"."audit_logs_2026_02" USING "btree" ("user_id");



CREATE INDEX "audit_logs_2026_03_action_idx" ON "public"."audit_logs_2026_03" USING "btree" ("action");



CREATE INDEX "audit_logs_2026_03_session_id_idx" ON "public"."audit_logs_2026_03" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "audit_logs_2026_03_user_id_idx" ON "public"."audit_logs_2026_03" USING "btree" ("user_id");



CREATE INDEX "audit_logs_2026_04_action_idx" ON "public"."audit_logs_2026_04" USING "btree" ("action");



CREATE INDEX "audit_logs_2026_04_session_id_idx" ON "public"."audit_logs_2026_04" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "audit_logs_2026_04_user_id_idx" ON "public"."audit_logs_2026_04" USING "btree" ("user_id");



CREATE INDEX "audit_logs_2026_05_action_idx" ON "public"."audit_logs_2026_05" USING "btree" ("action");



CREATE INDEX "audit_logs_2026_05_session_id_idx" ON "public"."audit_logs_2026_05" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "audit_logs_2026_05_user_id_idx" ON "public"."audit_logs_2026_05" USING "btree" ("user_id");



CREATE INDEX "audit_logs_2026_06_action_idx" ON "public"."audit_logs_2026_06" USING "btree" ("action");



CREATE INDEX "audit_logs_2026_06_session_id_idx" ON "public"."audit_logs_2026_06" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "audit_logs_2026_06_user_id_idx" ON "public"."audit_logs_2026_06" USING "btree" ("user_id");



CREATE INDEX "audit_logs_2026_07_action_idx" ON "public"."audit_logs_2026_07" USING "btree" ("action");



CREATE INDEX "audit_logs_2026_07_session_id_idx" ON "public"."audit_logs_2026_07" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "audit_logs_2026_07_user_id_idx" ON "public"."audit_logs_2026_07" USING "btree" ("user_id");



CREATE INDEX "audit_logs_2026_08_action_idx" ON "public"."audit_logs_2026_08" USING "btree" ("action");



CREATE INDEX "audit_logs_2026_08_session_id_idx" ON "public"."audit_logs_2026_08" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "audit_logs_2026_08_user_id_idx" ON "public"."audit_logs_2026_08" USING "btree" ("user_id");



CREATE INDEX "audit_logs_2026_09_action_idx" ON "public"."audit_logs_2026_09" USING "btree" ("action");



CREATE INDEX "audit_logs_2026_09_session_id_idx" ON "public"."audit_logs_2026_09" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "audit_logs_2026_09_user_id_idx" ON "public"."audit_logs_2026_09" USING "btree" ("user_id");



CREATE INDEX "audit_logs_2026_10_action_idx" ON "public"."audit_logs_2026_10" USING "btree" ("action");



CREATE INDEX "audit_logs_2026_10_session_id_idx" ON "public"."audit_logs_2026_10" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "audit_logs_2026_10_user_id_idx" ON "public"."audit_logs_2026_10" USING "btree" ("user_id");



CREATE INDEX "audit_logs_2026_11_action_idx" ON "public"."audit_logs_2026_11" USING "btree" ("action");



CREATE INDEX "audit_logs_2026_11_session_id_idx" ON "public"."audit_logs_2026_11" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "audit_logs_2026_11_user_id_idx" ON "public"."audit_logs_2026_11" USING "btree" ("user_id");



CREATE INDEX "audit_logs_2026_12_action_idx" ON "public"."audit_logs_2026_12" USING "btree" ("action");



CREATE INDEX "audit_logs_2026_12_session_id_idx" ON "public"."audit_logs_2026_12" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "audit_logs_2026_12_user_id_idx" ON "public"."audit_logs_2026_12" USING "btree" ("user_id");



CREATE INDEX "audit_logs_2027_01_action_idx" ON "public"."audit_logs_2027_01" USING "btree" ("action");



CREATE INDEX "audit_logs_2027_01_session_id_idx" ON "public"."audit_logs_2027_01" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "audit_logs_2027_01_user_id_idx" ON "public"."audit_logs_2027_01" USING "btree" ("user_id");



CREATE INDEX "audit_logs_2027_02_action_idx" ON "public"."audit_logs_2027_02" USING "btree" ("action");



CREATE INDEX "audit_logs_2027_02_session_id_idx" ON "public"."audit_logs_2027_02" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "audit_logs_2027_02_user_id_idx" ON "public"."audit_logs_2027_02" USING "btree" ("user_id");



CREATE INDEX "audit_logs_2027_03_action_idx" ON "public"."audit_logs_2027_03" USING "btree" ("action");



CREATE INDEX "audit_logs_2027_03_session_id_idx" ON "public"."audit_logs_2027_03" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "audit_logs_2027_03_user_id_idx" ON "public"."audit_logs_2027_03" USING "btree" ("user_id");



CREATE INDEX "audit_logs_2027_04_action_idx" ON "public"."audit_logs_2027_04" USING "btree" ("action");



CREATE INDEX "audit_logs_2027_04_session_id_idx" ON "public"."audit_logs_2027_04" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "audit_logs_2027_04_user_id_idx" ON "public"."audit_logs_2027_04" USING "btree" ("user_id");



CREATE INDEX "audit_logs_2027_05_action_idx" ON "public"."audit_logs_2027_05" USING "btree" ("action");



CREATE INDEX "audit_logs_2027_05_session_id_idx" ON "public"."audit_logs_2027_05" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "audit_logs_2027_05_user_id_idx" ON "public"."audit_logs_2027_05" USING "btree" ("user_id");



CREATE INDEX "audit_logs_2027_06_action_idx" ON "public"."audit_logs_2027_06" USING "btree" ("action");



CREATE INDEX "audit_logs_2027_06_session_id_idx" ON "public"."audit_logs_2027_06" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "audit_logs_2027_06_user_id_idx" ON "public"."audit_logs_2027_06" USING "btree" ("user_id");



CREATE INDEX "audit_logs_2027_07_action_idx" ON "public"."audit_logs_2027_07" USING "btree" ("action");



CREATE INDEX "audit_logs_2027_07_session_id_idx" ON "public"."audit_logs_2027_07" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "audit_logs_2027_07_user_id_idx" ON "public"."audit_logs_2027_07" USING "btree" ("user_id");



CREATE INDEX "audit_logs_2027_08_action_idx" ON "public"."audit_logs_2027_08" USING "btree" ("action");



CREATE INDEX "audit_logs_2027_08_session_id_idx" ON "public"."audit_logs_2027_08" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "audit_logs_2027_08_user_id_idx" ON "public"."audit_logs_2027_08" USING "btree" ("user_id");



CREATE INDEX "audit_logs_2027_09_action_idx" ON "public"."audit_logs_2027_09" USING "btree" ("action");



CREATE INDEX "audit_logs_2027_09_session_id_idx" ON "public"."audit_logs_2027_09" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "audit_logs_2027_09_user_id_idx" ON "public"."audit_logs_2027_09" USING "btree" ("user_id");



CREATE INDEX "audit_logs_2027_10_action_idx" ON "public"."audit_logs_2027_10" USING "btree" ("action");



CREATE INDEX "audit_logs_2027_10_session_id_idx" ON "public"."audit_logs_2027_10" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "audit_logs_2027_10_user_id_idx" ON "public"."audit_logs_2027_10" USING "btree" ("user_id");



CREATE INDEX "audit_logs_2027_11_action_idx" ON "public"."audit_logs_2027_11" USING "btree" ("action");



CREATE INDEX "audit_logs_2027_11_session_id_idx" ON "public"."audit_logs_2027_11" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "audit_logs_2027_11_user_id_idx" ON "public"."audit_logs_2027_11" USING "btree" ("user_id");



CREATE INDEX "audit_logs_2027_12_action_idx" ON "public"."audit_logs_2027_12" USING "btree" ("action");



CREATE INDEX "audit_logs_2027_12_session_id_idx" ON "public"."audit_logs_2027_12" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "audit_logs_2027_12_user_id_idx" ON "public"."audit_logs_2027_12" USING "btree" ("user_id");



CREATE INDEX "audit_logs_2028_01_action_idx" ON "public"."audit_logs_2028_01" USING "btree" ("action");



CREATE INDEX "audit_logs_2028_01_session_id_idx" ON "public"."audit_logs_2028_01" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "audit_logs_2028_01_user_id_idx" ON "public"."audit_logs_2028_01" USING "btree" ("user_id");



CREATE INDEX "audit_logs_2028_02_action_idx" ON "public"."audit_logs_2028_02" USING "btree" ("action");



CREATE INDEX "audit_logs_2028_02_session_id_idx" ON "public"."audit_logs_2028_02" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "audit_logs_2028_02_user_id_idx" ON "public"."audit_logs_2028_02" USING "btree" ("user_id");



CREATE INDEX "audit_logs_2028_03_action_idx" ON "public"."audit_logs_2028_03" USING "btree" ("action");



CREATE INDEX "audit_logs_2028_03_session_id_idx" ON "public"."audit_logs_2028_03" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "audit_logs_2028_03_user_id_idx" ON "public"."audit_logs_2028_03" USING "btree" ("user_id");



CREATE INDEX "audit_logs_2028_04_action_idx" ON "public"."audit_logs_2028_04" USING "btree" ("action");



CREATE INDEX "audit_logs_2028_04_session_id_idx" ON "public"."audit_logs_2028_04" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "audit_logs_2028_04_user_id_idx" ON "public"."audit_logs_2028_04" USING "btree" ("user_id");



CREATE INDEX "audit_logs_2028_05_action_idx" ON "public"."audit_logs_2028_05" USING "btree" ("action");



CREATE INDEX "audit_logs_2028_05_session_id_idx" ON "public"."audit_logs_2028_05" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "audit_logs_2028_05_user_id_idx" ON "public"."audit_logs_2028_05" USING "btree" ("user_id");



CREATE INDEX "audit_logs_2028_06_action_idx" ON "public"."audit_logs_2028_06" USING "btree" ("action");



CREATE INDEX "audit_logs_2028_06_session_id_idx" ON "public"."audit_logs_2028_06" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "audit_logs_2028_06_user_id_idx" ON "public"."audit_logs_2028_06" USING "btree" ("user_id");



CREATE INDEX "audit_logs_2028_07_action_idx" ON "public"."audit_logs_2028_07" USING "btree" ("action");



CREATE INDEX "audit_logs_2028_07_session_id_idx" ON "public"."audit_logs_2028_07" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "audit_logs_2028_07_user_id_idx" ON "public"."audit_logs_2028_07" USING "btree" ("user_id");



CREATE INDEX "audit_logs_2028_08_action_idx" ON "public"."audit_logs_2028_08" USING "btree" ("action");



CREATE INDEX "audit_logs_2028_08_session_id_idx" ON "public"."audit_logs_2028_08" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "audit_logs_2028_08_user_id_idx" ON "public"."audit_logs_2028_08" USING "btree" ("user_id");



CREATE INDEX "audit_logs_2028_09_action_idx" ON "public"."audit_logs_2028_09" USING "btree" ("action");



CREATE INDEX "audit_logs_2028_09_session_id_idx" ON "public"."audit_logs_2028_09" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "audit_logs_2028_09_user_id_idx" ON "public"."audit_logs_2028_09" USING "btree" ("user_id");



CREATE INDEX "audit_logs_2028_10_action_idx" ON "public"."audit_logs_2028_10" USING "btree" ("action");



CREATE INDEX "audit_logs_2028_10_session_id_idx" ON "public"."audit_logs_2028_10" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "audit_logs_2028_10_user_id_idx" ON "public"."audit_logs_2028_10" USING "btree" ("user_id");



CREATE INDEX "audit_logs_2028_11_action_idx" ON "public"."audit_logs_2028_11" USING "btree" ("action");



CREATE INDEX "audit_logs_2028_11_session_id_idx" ON "public"."audit_logs_2028_11" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "audit_logs_2028_11_user_id_idx" ON "public"."audit_logs_2028_11" USING "btree" ("user_id");



CREATE INDEX "audit_logs_2028_12_action_idx" ON "public"."audit_logs_2028_12" USING "btree" ("action");



CREATE INDEX "audit_logs_2028_12_session_id_idx" ON "public"."audit_logs_2028_12" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "audit_logs_2028_12_user_id_idx" ON "public"."audit_logs_2028_12" USING "btree" ("user_id");



CREATE INDEX "audit_logs_default_action_idx" ON "public"."audit_logs_default" USING "btree" ("action");



CREATE INDEX "audit_logs_default_session_id_idx" ON "public"."audit_logs_default" USING "btree" ("session_id") WHERE ("session_id" IS NOT NULL);



CREATE INDEX "audit_logs_default_user_id_idx" ON "public"."audit_logs_default" USING "btree" ("user_id");



CREATE INDEX "idx_appointment_cancellations_appointment_id" ON "public"."appointment_cancellations" USING "btree" ("appointment_id");



CREATE INDEX "idx_appointment_cancellations_cancelled_at" ON "public"."appointment_cancellations" USING "btree" ("cancelled_at" DESC);



CREATE INDEX "idx_appointment_tokens_appointment_id" ON "public"."appointment_tokens" USING "btree" ("appointment_id");



CREATE INDEX "idx_appointment_tokens_expires" ON "public"."appointment_tokens" USING "btree" ("expires_at") WHERE ("used_at" IS NULL);



CREATE INDEX "idx_appointment_tokens_token" ON "public"."appointment_tokens" USING "btree" ("token") WHERE ("used_at" IS NULL);



CREATE INDEX "idx_appointments_barber" ON "public"."appointments_legacy" USING "btree" ("barber_id");



CREATE INDEX "idx_appointments_barber_date" ON "public"."appointments_legacy" USING "btree" ("barber_id", "appointment_date", "appointment_time");



CREATE INDEX "idx_appointments_barber_id" ON "public"."appointments_legacy" USING "btree" ("barber_id");



CREATE INDEX "idx_appointments_barbershop" ON "public"."appointments_legacy" USING "btree" ("barbershop_id");



CREATE INDEX "idx_appointments_barbershop_date" ON "public"."appointments_legacy" USING "btree" ("barbershop_id", "appointment_date", "appointment_time");



CREATE INDEX "idx_appointments_barbershop_id" ON "public"."appointments_legacy" USING "btree" ("barbershop_id");



CREATE INDEX "idx_appointments_barbershop_status" ON "public"."appointments_legacy" USING "btree" ("barbershop_id", "status");



CREATE INDEX "idx_appointments_booking_lookup" ON "public"."appointments_legacy" USING "btree" ("barbershop_id", "barber_id", "appointment_date", "appointment_time") WHERE ("status" <> ALL (ARRAY['cancelled'::"text", 'completed'::"text"]));



CREATE INDEX "idx_appointments_composite" ON "public"."appointments_legacy" USING "btree" ("barbershop_id", "appointment_date", "appointment_time");



CREATE INDEX "idx_appointments_conflict" ON "public"."appointments_legacy" USING "btree" ("barber_id", "appointment_date", "status");



COMMENT ON INDEX "public"."idx_appointments_conflict" IS 'Acelera verificação de horários disponíveis';



CREATE INDEX "idx_appointments_customer_history" ON "public"."appointments_legacy" USING "btree" ("customer_id", "created_at" DESC);



CREATE INDEX "idx_appointments_customer_id" ON "public"."appointments_legacy" USING "btree" ("customer_id");



CREATE INDEX "idx_appointments_customer_lookup" ON "public"."appointments_legacy" USING "btree" ("customer_id");



CREATE INDEX "idx_appointments_dashboard" ON "public"."appointments_legacy" USING "btree" ("barbershop_id", "created_at", "status");



CREATE INDEX "idx_appointments_dashboard_perf" ON "public"."appointments_legacy" USING "btree" ("barbershop_id", "appointment_date", "appointment_time");



CREATE INDEX "idx_appointments_date" ON "public"."appointments_legacy" USING "btree" ("appointment_date");



CREATE INDEX "idx_appointments_history" ON "public"."appointments_legacy" USING "btree" ("customer_id", "appointment_date") WHERE ("status" = 'completed'::"text");



COMMENT ON INDEX "public"."idx_appointments_history" IS 'Accelerates retention calculations by indexing completed appointments (previously ignored by other indexes).';



CREATE INDEX "idx_appointments_lookup" ON "public"."appointments_legacy" USING "btree" ("barbershop_id", "barber_id", "appointment_date", "appointment_time") WHERE ("status" = ANY (ARRAY['confirmed'::"text", 'pending'::"text"]));



COMMENT ON INDEX "public"."idx_appointments_lookup" IS 'Índice composto para busca rápida de horários reservados';



CREATE INDEX "idx_appointments_notification_poll" ON "public"."appointments_legacy" USING "btree" ("status", "reminder_24h_sent", "reminder_1h_sent", "appointment_date", "appointment_time") WHERE ("status" = 'confirmed'::"text");



CREATE INDEX "idx_appointments_reminders" ON "public"."appointments_legacy" USING "btree" ("appointment_date", "reminder_24h_sent", "reminder_1h_sent") WHERE ("status" = 'confirmed'::"text");



CREATE INDEX "idx_appointments_schedule_composite" ON "public"."appointments_legacy" USING "btree" ("barber_id", "appointment_date", "appointment_time");



CREATE INDEX "idx_appointments_service_id" ON "public"."appointments_legacy" USING "btree" ("service_id");



CREATE INDEX "idx_appointments_status" ON "public"."appointments_legacy" USING "btree" ("status") WHERE ("status" = ANY (ARRAY['pending'::"text", 'confirmed'::"text"]));



CREATE INDEX "idx_appointments_token_lookup" ON "public"."appointments_legacy" USING "btree" ("barbershop_id") WHERE ("status" = ANY (ARRAY['confirmed'::"text", 'pending'::"text"]));



CREATE UNIQUE INDEX "idx_appointments_unique_slot" ON "public"."appointments_legacy" USING "btree" ("barber_id", "appointment_date", "appointment_time") WHERE ("status" <> ALL (ARRAY['cancelled'::"text", 'no_show'::"text", 'rejected'::"text"]));



COMMENT ON INDEX "public"."idx_appointments_unique_slot" IS 'CRITICAL: Impede agendamento duplicado no nível do banco. Garante que o catch de unique_violation na RPC funcione.';



CREATE UNIQUE INDEX "idx_appointments_unique_slot_v3" ON "public"."appointments_legacy" USING "btree" ("barber_id", "appointment_date", "appointment_time") WHERE ("status" <> ALL (ARRAY['cancelled'::"text", 'rejected'::"text"]));



COMMENT ON INDEX "public"."idx_appointments_unique_slot_v3" IS 'Sovereign Architecture Lock: Previne fisicamente agendamentos duplicados.';



CREATE INDEX "idx_audit_created_at" ON "public"."sovereign_audit_events" USING "btree" ("created_at" DESC);



CREATE INDEX "idx_audit_event_type" ON "public"."sovereign_audit_events" USING "btree" ("event_type");



CREATE INDEX "idx_audit_severity" ON "public"."sovereign_audit_events" USING "btree" ("severity");



CREATE INDEX "idx_audit_user_id" ON "public"."sovereign_audit_events" USING "btree" ("user_id");



CREATE INDEX "idx_auth_otps_expires_at" ON "public"."auth_otps" USING "btree" ("expires_at");



CREATE INDEX "idx_backup_codes_user" ON "public"."backup_codes" USING "btree" ("user_id") WHERE ("used_at" IS NULL);



CREATE INDEX "idx_barbers_barbershop" ON "public"."barbers" USING "btree" ("barbershop_id");



CREATE INDEX "idx_barbers_barbershop_active" ON "public"."barbers" USING "btree" ("barbershop_id", "is_active");



CREATE INDEX "idx_barbers_count_active" ON "public"."barbers" USING "btree" ("barbershop_id") WHERE ("is_active" = true);



CREATE INDEX "idx_barbers_user_id" ON "public"."barbers" USING "btree" ("user_id");



CREATE INDEX "idx_barbershops_deleted_at" ON "public"."barbershops" USING "btree" ("deleted_at") WHERE ("deleted_at" IS NOT NULL);



CREATE INDEX "idx_barbershops_owner" ON "public"."barbershops" USING "btree" ("owner_id");



CREATE INDEX "idx_barbershops_owner_id" ON "public"."barbershops" USING "btree" ("owner_id");



CREATE INDEX "idx_barbershops_slug" ON "public"."barbershops" USING "btree" ("slug");



CREATE INDEX "idx_barbershops_slug_active" ON "public"."barbershops" USING "btree" ("slug") WHERE ("subscription_status" <> 'cancelled'::"text");



COMMENT ON INDEX "public"."idx_barbershops_slug_active" IS 'Índice parcial para busca rápida de barbearias ativas por slug';



CREATE UNIQUE INDEX "idx_barbershops_slug_lower" ON "public"."barbershops" USING "btree" ("lower"("slug"));



COMMENT ON INDEX "public"."idx_barbershops_slug_lower" IS 'Ensures case-insensitive uniqueness for barbershop URLs.';



CREATE INDEX "idx_barbershops_subscription_ends_at" ON "public"."barbershops" USING "btree" ("subscription_ends_at") WHERE ("subscription_status" = 'active'::"text");



CREATE INDEX "idx_bi_log_date" ON "public"."bi_log" USING "btree" ("metric_date");



CREATE INDEX "idx_bi_log_tenant" ON "public"."bi_log" USING "btree" ("tenant_id");



CREATE INDEX "idx_commissions_appointment" ON "public"."commissions" USING "btree" ("appointment_id");



CREATE INDEX "idx_commissions_barber" ON "public"."commissions" USING "btree" ("barber_id");



CREATE INDEX "idx_commissions_barber_date" ON "public"."commissions" USING "btree" ("barber_id", "reference_date");



CREATE INDEX "idx_commissions_barbershop" ON "public"."commissions" USING "btree" ("barbershop_id");



CREATE INDEX "idx_commissions_date" ON "public"."commissions" USING "btree" ("reference_date");



CREATE INDEX "idx_commissions_paid" ON "public"."commissions" USING "btree" ("is_paid");



CREATE INDEX "idx_commissions_reporting" ON "public"."commissions" USING "btree" ("barber_id", "created_at");



CREATE INDEX "idx_commissions_sale_id" ON "public"."commissions" USING "btree" ("sale_id");



CREATE INDEX "idx_cron_health_logs_execution_time" ON "public"."cron_health_logs" USING "btree" ("execution_time" DESC);



CREATE INDEX "idx_cron_health_logs_job_name" ON "public"."cron_health_logs" USING "btree" ("job_name");



CREATE INDEX "idx_cron_health_logs_status" ON "public"."cron_health_logs" USING "btree" ("status");



CREATE INDEX "idx_csp_violations_barbershop" ON "public"."csp_violations" USING "btree" ("barbershop_id");



CREATE INDEX "idx_csp_violations_blocked_uri" ON "public"."csp_violations" USING "btree" ("blocked_uri");



CREATE INDEX "idx_csp_violations_created_at" ON "public"."csp_violations" USING "btree" ("created_at" DESC);



CREATE INDEX "idx_csp_violations_directive" ON "public"."csp_violations" USING "btree" ("violated_directive");



CREATE INDEX "idx_csp_violations_duplicate" ON "public"."csp_violations" USING "btree" ("barbershop_id", "blocked_uri", "violated_directive", "document_uri");



CREATE INDEX "idx_customer_magic_links_customer_id" ON "public"."customer_magic_links" USING "btree" ("customer_id");



CREATE INDEX "idx_customers_anonymization" ON "public"."customers" USING "btree" ("created_at") WHERE ("name" <> 'ANONIMIZADO'::"text");



CREATE INDEX "idx_customers_barbershop" ON "public"."customers" USING "btree" ("barbershop_id");



CREATE INDEX "idx_customers_is_active" ON "public"."customers" USING "btree" ("is_active");



CREATE INDEX "idx_customers_lookup" ON "public"."customers" USING "btree" ("barbershop_id", "phone");



CREATE INDEX "idx_customers_phone" ON "public"."customers" USING "btree" ("barbershop_id", "phone");



CREATE INDEX "idx_customers_user_id" ON "public"."customers" USING "btree" ("user_id");



CREATE INDEX "idx_daily_metrics_date" ON "public"."daily_metrics" USING "btree" ("date");



CREATE INDEX "idx_expenses_barbershop_id" ON "public"."expenses" USING "btree" ("barbershop_id");



CREATE INDEX "idx_financial_ledger_bs_date" ON "public"."financial_ledger" USING "btree" ("barbershop_id", "created_at");



CREATE INDEX "idx_ledger_barber" ON "public"."financial_ledger" USING "btree" ("barber_id");



CREATE INDEX "idx_ledger_barbershop" ON "public"."financial_ledger" USING "btree" ("barbershop_id");



CREATE INDEX "idx_ledger_date" ON "public"."financial_ledger" USING "btree" ("created_at");



CREATE INDEX "idx_ledger_type" ON "public"."financial_ledger" USING "btree" ("transaction_type");



CREATE INDEX "idx_login_attempts_attempted_at" ON "public"."login_attempts" USING "btree" ("attempted_at" DESC);



CREATE INDEX "idx_login_attempts_cleanup" ON "public"."login_attempts" USING "btree" ("attempted_at") WHERE ("success" = false);



CREATE INDEX "idx_login_attempts_email" ON "public"."login_attempts" USING "btree" ("email");



CREATE INDEX "idx_login_attempts_email_time" ON "public"."login_attempts" USING "btree" ("email", "attempt_time" DESC);



CREATE INDEX "idx_login_attempts_failures" ON "public"."login_attempts" USING "btree" ("email", "attempted_at") WHERE ("success" = false);



CREATE INDEX "idx_logs_cleanup" ON "public"."whatsapp_logs" USING "btree" ("created_at");



CREATE INDEX "idx_loyalty_barbershop_customer" ON "public"."loyalty_points" USING "btree" ("barbershop_id", "customer_id");



CREATE INDEX "idx_loyalty_points_customer" ON "public"."loyalty_points" USING "btree" ("barbershop_id", "customer_id");



CREATE INDEX "idx_loyalty_points_customer_id" ON "public"."loyalty_points" USING "btree" ("customer_id");



CREATE INDEX "idx_magic_links_expiration" ON "public"."customer_magic_links" USING "btree" ("expires_at");



CREATE INDEX "idx_mfa_recovery_ip_time" ON "public"."mfa_recovery_attempts" USING "btree" ("ip_address", "attempted_at" DESC);



CREATE INDEX "idx_mfa_recovery_user_time" ON "public"."mfa_recovery_attempts" USING "btree" ("user_id", "attempted_at" DESC);



CREATE INDEX "idx_notification_queue_poll" ON "public"."notification_queue" USING "btree" ("status", "next_retry_at") WHERE ("status" = 'pending'::"text");



CREATE INDEX "idx_permission_audit_action" ON "public"."permission_audit_log" USING "btree" ("action");



CREATE INDEX "idx_permission_audit_created_at" ON "public"."permission_audit_log" USING "btree" ("created_at" DESC);



CREATE INDEX "idx_permission_audit_target_user_id" ON "public"."permission_audit_log" USING "btree" ("target_user_id");



CREATE INDEX "idx_permission_audit_user_id" ON "public"."permission_audit_log" USING "btree" ("user_id");



CREATE INDEX "idx_products_barbershop" ON "public"."products" USING "btree" ("barbershop_id");



CREATE INDEX "idx_public_barbers_slug" ON "public"."barbers" USING "btree" ("barbershop_id") WHERE ("is_active" = true);



CREATE INDEX "idx_public_services_slug" ON "public"."services" USING "btree" ("barbershop_id") WHERE ("is_active" = true);



CREATE INDEX "idx_rate_limits_window_cleanup" ON "public"."rate_limits" USING "btree" ("window_start");



CREATE INDEX "idx_rate_limits_window_start" ON "public"."rate_limits" USING "btree" ("window_start");



CREATE INDEX "idx_salary_expenses_barber_id" ON "public"."salary_expenses" USING "btree" ("barber_id");



CREATE INDEX "idx_salary_expenses_barbershop_id" ON "public"."salary_expenses" USING "btree" ("barbershop_id");



CREATE INDEX "idx_sale_items_product_id" ON "public"."sale_items" USING "btree" ("product_id");



CREATE INDEX "idx_sale_items_sale" ON "public"."sale_items" USING "btree" ("sale_id");



CREATE INDEX "idx_sales_appointment" ON "public"."sales" USING "btree" ("appointment_id");



CREATE INDEX "idx_sales_barber_id" ON "public"."sales" USING "btree" ("barber_id");



CREATE INDEX "idx_sales_barbershop" ON "public"."sales" USING "btree" ("barbershop_id");



CREATE INDEX "idx_sales_customer" ON "public"."sales" USING "btree" ("customer_id");



CREATE INDEX "idx_sales_date" ON "public"."sales" USING "btree" ("sale_date");



CREATE INDEX "idx_security_events_alerted" ON "public"."security_events" USING "btree" ("alerted") WHERE ("alerted" = false);



CREATE INDEX "idx_security_events_created_at" ON "public"."security_events" USING "btree" ("created_at" DESC);



CREATE INDEX "idx_security_events_severity" ON "public"."security_events" USING "btree" ("severity");



CREATE INDEX "idx_security_events_type" ON "public"."security_events" USING "btree" ("type");



CREATE INDEX "idx_security_events_user_id" ON "public"."security_events" USING "btree" ("user_id");



CREATE INDEX "idx_services_barbershop" ON "public"."services" USING "btree" ("barbershop_id");



CREATE INDEX "idx_services_barbershop_active" ON "public"."services" USING "btree" ("barbershop_id", "is_active");



CREATE INDEX "idx_subscription_logs_barbershop_id" ON "public"."subscription_logs" USING "btree" ("barbershop_id");



CREATE INDEX "idx_subscription_logs_created_at" ON "public"."subscription_logs" USING "btree" ("created_at" DESC);



CREATE INDEX "idx_subscriptions_user_id" ON "public"."subscriptions" USING "btree" ("user_id");



CREATE UNIQUE INDEX "idx_unique_active_appointment" ON "public"."appointments_legacy" USING "btree" ("barber_id", "appointment_date", "appointment_time") WHERE ("status" <> ALL (ARRAY['cancelled'::"text", 'no_show'::"text"]));



COMMENT ON INDEX "public"."idx_unique_active_appointment" IS 'Previne double-booking: apenas 1 agendamento ativo por barbeiro/horário';



CREATE INDEX "idx_user_events_barbershop_id" ON "public"."user_events" USING "btree" ("barbershop_id");



CREATE INDEX "idx_user_events_created_at" ON "public"."user_events" USING "btree" ("created_at" DESC);



CREATE INDEX "idx_user_events_event_type" ON "public"."user_events" USING "btree" ("event_type");



CREATE INDEX "idx_user_events_user_id" ON "public"."user_events" USING "btree" ("user_id");



CREATE INDEX "idx_user_roles_barbershop_id" ON "public"."user_roles" USING "btree" ("barbershop_id");



CREATE INDEX "idx_webhook_events_status_retry" ON "public"."webhook_events" USING "btree" ("status", "next_retry_at") WHERE ("status" = ANY (ARRAY['pending'::"text", 'failed'::"text"]));



CREATE INDEX "idx_webhook_events_worker_heartbeat" ON "public"."webhook_events" USING "btree" ("worker_id", "last_heartbeat") WHERE ("worker_id" IS NOT NULL);



CREATE INDEX "idx_whatsapp_logs_appointment" ON "public"."whatsapp_logs" USING "btree" ("appointment_id");



CREATE INDEX "idx_whatsapp_logs_barbershop" ON "public"."whatsapp_logs" USING "btree" ("barbershop_id");



CREATE INDEX "idx_whatsapp_logs_barbershop_created" ON "public"."whatsapp_logs" USING "btree" ("barbershop_id", "created_at" DESC);



CREATE INDEX "idx_whatsapp_logs_cooldown" ON "public"."whatsapp_logs" USING "btree" ("barbershop_id", "template_name", "created_at" DESC);



CREATE INDEX "idx_whatsapp_logs_cooldown_check" ON "public"."whatsapp_logs" USING "btree" ("phone_number", "message_type", "sent_at" DESC);



CREATE UNIQUE INDEX "idx_whatsapp_logs_idempotency" ON "public"."whatsapp_logs" USING "btree" ("idempotency_key") WHERE ("idempotency_key" IS NOT NULL);



CREATE INDEX "idx_whatsapp_logs_idempotency_key" ON "public"."whatsapp_logs" USING "btree" ("idempotency_key") WHERE ("idempotency_key" IS NOT NULL);



CREATE INDEX "idx_whatsapp_logs_megaapi_message_id" ON "public"."whatsapp_logs" USING "btree" ("megaapi_message_id");



CREATE INDEX "idx_whatsapp_logs_phone_status" ON "public"."whatsapp_logs" USING "btree" ("phone_number", "status", "created_at" DESC);



CREATE INDEX "idx_whatsapp_logs_sent_at" ON "public"."whatsapp_logs" USING "btree" ("sent_at" DESC);



CREATE INDEX "idx_whatsapp_retry_cleanup" ON "public"."whatsapp_retry_queue" USING "btree" ("updated_at") WHERE ("status" = ANY (ARRAY['completed'::"text", 'failed'::"text"]));



CREATE INDEX "idx_whatsapp_retry_consumer" ON "public"."whatsapp_retry_queue" USING "btree" ("status", "next_retry_at") WHERE ("status" = 'pending'::"text");



CREATE INDEX "idx_whatsapp_retry_next_retry" ON "public"."whatsapp_retry_queue" USING "btree" ("next_retry_at") WHERE ("status" = 'pending'::"text");



CREATE INDEX "idx_whatsapp_retry_queue_appointment_id" ON "public"."whatsapp_retry_queue" USING "btree" ("appointment_id");



CREATE INDEX "idx_whatsapp_retry_queue_next_retry" ON "public"."whatsapp_retry_queue" USING "btree" ("next_retry_at") WHERE ("status" = 'pending'::"text");



CREATE INDEX "idx_whatsapp_retry_queue_status" ON "public"."whatsapp_retry_queue" USING "btree" ("status") WHERE ("status" = 'pending'::"text");



CREATE INDEX "idx_whatsapp_retry_self_healing" ON "public"."whatsapp_retry_queue" USING "btree" ("status", "updated_at") WHERE ("status" = 'processing'::"text");



CREATE INDEX "idx_whatsapp_retry_status_next_retry" ON "public"."whatsapp_retry_queue" USING "btree" ("status", "next_retry_at");



CREATE INDEX "idx_whatsapp_retry_worker_poll" ON "public"."whatsapp_retry_queue" USING "btree" ("status", "next_retry_at") WHERE ("status" = 'pending'::"text");



ALTER INDEX "public"."idx_appointments_v5_date" ATTACH PARTITION "public"."appointments_default_appointment_date_idx";



ALTER INDEX "public"."idx_appointments_retention" ATTACH PARTITION "public"."appointments_default_appointment_date_idx1";



ALTER INDEX "public"."idx_unique_active_slot" ATTACH PARTITION "public"."appointments_default_barber_id_appointment_date_appointment_idx";



ALTER INDEX "public"."idx_appointments_v5_barber_date" ATTACH PARTITION "public"."appointments_default_barber_id_appointment_date_idx";



ALTER INDEX "public"."idx_appointments_bs_date" ATTACH PARTITION "public"."appointments_default_barbershop_id_appointment_date_idx";



ALTER INDEX "public"."idx_appointments_v5_barbershop" ATTACH PARTITION "public"."appointments_default_barbershop_id_idx";



ALTER INDEX "public"."idx_appointments_v5_created_at" ATTACH PARTITION "public"."appointments_default_created_at_idx";



ALTER INDEX "public"."idx_appointments_v5_customer" ATTACH PARTITION "public"."appointments_default_customer_id_idx";



ALTER INDEX "public"."appointments_pkey1" ATTACH PARTITION "public"."appointments_default_pkey";



ALTER INDEX "public"."idx_appointments_v5_status" ATTACH PARTITION "public"."appointments_default_status_idx";



ALTER INDEX "public"."idx_appointments_v5_date" ATTACH PARTITION "public"."appointments_p2024_appointment_date_idx";



ALTER INDEX "public"."idx_appointments_retention" ATTACH PARTITION "public"."appointments_p2024_appointment_date_idx1";



ALTER INDEX "public"."idx_unique_active_slot" ATTACH PARTITION "public"."appointments_p2024_barber_id_appointment_date_appointment_t_idx";



ALTER INDEX "public"."idx_appointments_v5_barber_date" ATTACH PARTITION "public"."appointments_p2024_barber_id_appointment_date_idx";



ALTER INDEX "public"."idx_appointments_bs_date" ATTACH PARTITION "public"."appointments_p2024_barbershop_id_appointment_date_idx";



ALTER INDEX "public"."idx_appointments_v5_barbershop" ATTACH PARTITION "public"."appointments_p2024_barbershop_id_idx";



ALTER INDEX "public"."idx_appointments_v5_created_at" ATTACH PARTITION "public"."appointments_p2024_created_at_idx";



ALTER INDEX "public"."idx_appointments_v5_customer" ATTACH PARTITION "public"."appointments_p2024_customer_id_idx";



ALTER INDEX "public"."appointments_pkey1" ATTACH PARTITION "public"."appointments_p2024_pkey";



ALTER INDEX "public"."idx_appointments_v5_status" ATTACH PARTITION "public"."appointments_p2024_status_idx";



ALTER INDEX "public"."idx_appointments_v5_date" ATTACH PARTITION "public"."appointments_p2025_appointment_date_idx";



ALTER INDEX "public"."idx_appointments_retention" ATTACH PARTITION "public"."appointments_p2025_appointment_date_idx1";



ALTER INDEX "public"."idx_unique_active_slot" ATTACH PARTITION "public"."appointments_p2025_barber_id_appointment_date_appointment_t_idx";



ALTER INDEX "public"."idx_appointments_v5_barber_date" ATTACH PARTITION "public"."appointments_p2025_barber_id_appointment_date_idx";



ALTER INDEX "public"."idx_appointments_bs_date" ATTACH PARTITION "public"."appointments_p2025_barbershop_id_appointment_date_idx";



ALTER INDEX "public"."idx_appointments_v5_barbershop" ATTACH PARTITION "public"."appointments_p2025_barbershop_id_idx";



ALTER INDEX "public"."idx_appointments_v5_created_at" ATTACH PARTITION "public"."appointments_p2025_created_at_idx";



ALTER INDEX "public"."idx_appointments_v5_customer" ATTACH PARTITION "public"."appointments_p2025_customer_id_idx";



ALTER INDEX "public"."appointments_pkey1" ATTACH PARTITION "public"."appointments_p2025_pkey";



ALTER INDEX "public"."idx_appointments_v5_status" ATTACH PARTITION "public"."appointments_p2025_status_idx";



ALTER INDEX "public"."idx_appointments_v5_date" ATTACH PARTITION "public"."appointments_p2026_appointment_date_idx";



ALTER INDEX "public"."idx_appointments_retention" ATTACH PARTITION "public"."appointments_p2026_appointment_date_idx1";



ALTER INDEX "public"."idx_unique_active_slot" ATTACH PARTITION "public"."appointments_p2026_barber_id_appointment_date_appointment_t_idx";



ALTER INDEX "public"."idx_appointments_v5_barber_date" ATTACH PARTITION "public"."appointments_p2026_barber_id_appointment_date_idx";



ALTER INDEX "public"."idx_appointments_bs_date" ATTACH PARTITION "public"."appointments_p2026_barbershop_id_appointment_date_idx";



ALTER INDEX "public"."idx_appointments_v5_barbershop" ATTACH PARTITION "public"."appointments_p2026_barbershop_id_idx";



ALTER INDEX "public"."idx_appointments_v5_created_at" ATTACH PARTITION "public"."appointments_p2026_created_at_idx";



ALTER INDEX "public"."idx_appointments_v5_customer" ATTACH PARTITION "public"."appointments_p2026_customer_id_idx";



ALTER INDEX "public"."appointments_pkey1" ATTACH PARTITION "public"."appointments_p2026_pkey";



ALTER INDEX "public"."idx_appointments_v5_status" ATTACH PARTITION "public"."appointments_p2026_status_idx";



ALTER INDEX "public"."idx_audit_logs_action" ATTACH PARTITION "public"."audit_logs_2026_01_action_idx";



ALTER INDEX "public"."audit_logs_pkey1" ATTACH PARTITION "public"."audit_logs_2026_01_pkey";



ALTER INDEX "public"."idx_audit_logs_session_id" ATTACH PARTITION "public"."audit_logs_2026_01_session_id_idx";



ALTER INDEX "public"."idx_audit_logs_user_id" ATTACH PARTITION "public"."audit_logs_2026_01_user_id_idx";



ALTER INDEX "public"."idx_audit_logs_action" ATTACH PARTITION "public"."audit_logs_2026_02_action_idx";



ALTER INDEX "public"."audit_logs_pkey1" ATTACH PARTITION "public"."audit_logs_2026_02_pkey";



ALTER INDEX "public"."idx_audit_logs_session_id" ATTACH PARTITION "public"."audit_logs_2026_02_session_id_idx";



ALTER INDEX "public"."idx_audit_logs_user_id" ATTACH PARTITION "public"."audit_logs_2026_02_user_id_idx";



ALTER INDEX "public"."idx_audit_logs_action" ATTACH PARTITION "public"."audit_logs_2026_03_action_idx";



ALTER INDEX "public"."audit_logs_pkey1" ATTACH PARTITION "public"."audit_logs_2026_03_pkey";



ALTER INDEX "public"."idx_audit_logs_session_id" ATTACH PARTITION "public"."audit_logs_2026_03_session_id_idx";



ALTER INDEX "public"."idx_audit_logs_user_id" ATTACH PARTITION "public"."audit_logs_2026_03_user_id_idx";



ALTER INDEX "public"."idx_audit_logs_action" ATTACH PARTITION "public"."audit_logs_2026_04_action_idx";



ALTER INDEX "public"."audit_logs_pkey1" ATTACH PARTITION "public"."audit_logs_2026_04_pkey";



ALTER INDEX "public"."idx_audit_logs_session_id" ATTACH PARTITION "public"."audit_logs_2026_04_session_id_idx";



ALTER INDEX "public"."idx_audit_logs_user_id" ATTACH PARTITION "public"."audit_logs_2026_04_user_id_idx";



ALTER INDEX "public"."idx_audit_logs_action" ATTACH PARTITION "public"."audit_logs_2026_05_action_idx";



ALTER INDEX "public"."audit_logs_pkey1" ATTACH PARTITION "public"."audit_logs_2026_05_pkey";



ALTER INDEX "public"."idx_audit_logs_session_id" ATTACH PARTITION "public"."audit_logs_2026_05_session_id_idx";



ALTER INDEX "public"."idx_audit_logs_user_id" ATTACH PARTITION "public"."audit_logs_2026_05_user_id_idx";



ALTER INDEX "public"."idx_audit_logs_action" ATTACH PARTITION "public"."audit_logs_2026_06_action_idx";



ALTER INDEX "public"."audit_logs_pkey1" ATTACH PARTITION "public"."audit_logs_2026_06_pkey";



ALTER INDEX "public"."idx_audit_logs_session_id" ATTACH PARTITION "public"."audit_logs_2026_06_session_id_idx";



ALTER INDEX "public"."idx_audit_logs_user_id" ATTACH PARTITION "public"."audit_logs_2026_06_user_id_idx";



ALTER INDEX "public"."idx_audit_logs_action" ATTACH PARTITION "public"."audit_logs_2026_07_action_idx";



ALTER INDEX "public"."audit_logs_pkey1" ATTACH PARTITION "public"."audit_logs_2026_07_pkey";



ALTER INDEX "public"."idx_audit_logs_session_id" ATTACH PARTITION "public"."audit_logs_2026_07_session_id_idx";



ALTER INDEX "public"."idx_audit_logs_user_id" ATTACH PARTITION "public"."audit_logs_2026_07_user_id_idx";



ALTER INDEX "public"."idx_audit_logs_action" ATTACH PARTITION "public"."audit_logs_2026_08_action_idx";



ALTER INDEX "public"."audit_logs_pkey1" ATTACH PARTITION "public"."audit_logs_2026_08_pkey";



ALTER INDEX "public"."idx_audit_logs_session_id" ATTACH PARTITION "public"."audit_logs_2026_08_session_id_idx";



ALTER INDEX "public"."idx_audit_logs_user_id" ATTACH PARTITION "public"."audit_logs_2026_08_user_id_idx";



ALTER INDEX "public"."idx_audit_logs_action" ATTACH PARTITION "public"."audit_logs_2026_09_action_idx";



ALTER INDEX "public"."audit_logs_pkey1" ATTACH PARTITION "public"."audit_logs_2026_09_pkey";



ALTER INDEX "public"."idx_audit_logs_session_id" ATTACH PARTITION "public"."audit_logs_2026_09_session_id_idx";



ALTER INDEX "public"."idx_audit_logs_user_id" ATTACH PARTITION "public"."audit_logs_2026_09_user_id_idx";



ALTER INDEX "public"."idx_audit_logs_action" ATTACH PARTITION "public"."audit_logs_2026_10_action_idx";



ALTER INDEX "public"."audit_logs_pkey1" ATTACH PARTITION "public"."audit_logs_2026_10_pkey";



ALTER INDEX "public"."idx_audit_logs_session_id" ATTACH PARTITION "public"."audit_logs_2026_10_session_id_idx";



ALTER INDEX "public"."idx_audit_logs_user_id" ATTACH PARTITION "public"."audit_logs_2026_10_user_id_idx";



ALTER INDEX "public"."idx_audit_logs_action" ATTACH PARTITION "public"."audit_logs_2026_11_action_idx";



ALTER INDEX "public"."audit_logs_pkey1" ATTACH PARTITION "public"."audit_logs_2026_11_pkey";



ALTER INDEX "public"."idx_audit_logs_session_id" ATTACH PARTITION "public"."audit_logs_2026_11_session_id_idx";



ALTER INDEX "public"."idx_audit_logs_user_id" ATTACH PARTITION "public"."audit_logs_2026_11_user_id_idx";



ALTER INDEX "public"."idx_audit_logs_action" ATTACH PARTITION "public"."audit_logs_2026_12_action_idx";



ALTER INDEX "public"."audit_logs_pkey1" ATTACH PARTITION "public"."audit_logs_2026_12_pkey";



ALTER INDEX "public"."idx_audit_logs_session_id" ATTACH PARTITION "public"."audit_logs_2026_12_session_id_idx";



ALTER INDEX "public"."idx_audit_logs_user_id" ATTACH PARTITION "public"."audit_logs_2026_12_user_id_idx";



ALTER INDEX "public"."idx_audit_logs_action" ATTACH PARTITION "public"."audit_logs_2027_01_action_idx";



ALTER INDEX "public"."audit_logs_pkey1" ATTACH PARTITION "public"."audit_logs_2027_01_pkey";



ALTER INDEX "public"."idx_audit_logs_session_id" ATTACH PARTITION "public"."audit_logs_2027_01_session_id_idx";



ALTER INDEX "public"."idx_audit_logs_user_id" ATTACH PARTITION "public"."audit_logs_2027_01_user_id_idx";



ALTER INDEX "public"."idx_audit_logs_action" ATTACH PARTITION "public"."audit_logs_2027_02_action_idx";



ALTER INDEX "public"."audit_logs_pkey1" ATTACH PARTITION "public"."audit_logs_2027_02_pkey";



ALTER INDEX "public"."idx_audit_logs_session_id" ATTACH PARTITION "public"."audit_logs_2027_02_session_id_idx";



ALTER INDEX "public"."idx_audit_logs_user_id" ATTACH PARTITION "public"."audit_logs_2027_02_user_id_idx";



ALTER INDEX "public"."idx_audit_logs_action" ATTACH PARTITION "public"."audit_logs_2027_03_action_idx";



ALTER INDEX "public"."audit_logs_pkey1" ATTACH PARTITION "public"."audit_logs_2027_03_pkey";



ALTER INDEX "public"."idx_audit_logs_session_id" ATTACH PARTITION "public"."audit_logs_2027_03_session_id_idx";



ALTER INDEX "public"."idx_audit_logs_user_id" ATTACH PARTITION "public"."audit_logs_2027_03_user_id_idx";



ALTER INDEX "public"."idx_audit_logs_action" ATTACH PARTITION "public"."audit_logs_2027_04_action_idx";



ALTER INDEX "public"."audit_logs_pkey1" ATTACH PARTITION "public"."audit_logs_2027_04_pkey";



ALTER INDEX "public"."idx_audit_logs_session_id" ATTACH PARTITION "public"."audit_logs_2027_04_session_id_idx";



ALTER INDEX "public"."idx_audit_logs_user_id" ATTACH PARTITION "public"."audit_logs_2027_04_user_id_idx";



ALTER INDEX "public"."idx_audit_logs_action" ATTACH PARTITION "public"."audit_logs_2027_05_action_idx";



ALTER INDEX "public"."audit_logs_pkey1" ATTACH PARTITION "public"."audit_logs_2027_05_pkey";



ALTER INDEX "public"."idx_audit_logs_session_id" ATTACH PARTITION "public"."audit_logs_2027_05_session_id_idx";



ALTER INDEX "public"."idx_audit_logs_user_id" ATTACH PARTITION "public"."audit_logs_2027_05_user_id_idx";



ALTER INDEX "public"."idx_audit_logs_action" ATTACH PARTITION "public"."audit_logs_2027_06_action_idx";



ALTER INDEX "public"."audit_logs_pkey1" ATTACH PARTITION "public"."audit_logs_2027_06_pkey";



ALTER INDEX "public"."idx_audit_logs_session_id" ATTACH PARTITION "public"."audit_logs_2027_06_session_id_idx";



ALTER INDEX "public"."idx_audit_logs_user_id" ATTACH PARTITION "public"."audit_logs_2027_06_user_id_idx";



ALTER INDEX "public"."idx_audit_logs_action" ATTACH PARTITION "public"."audit_logs_2027_07_action_idx";



ALTER INDEX "public"."audit_logs_pkey1" ATTACH PARTITION "public"."audit_logs_2027_07_pkey";



ALTER INDEX "public"."idx_audit_logs_session_id" ATTACH PARTITION "public"."audit_logs_2027_07_session_id_idx";



ALTER INDEX "public"."idx_audit_logs_user_id" ATTACH PARTITION "public"."audit_logs_2027_07_user_id_idx";



ALTER INDEX "public"."idx_audit_logs_action" ATTACH PARTITION "public"."audit_logs_2027_08_action_idx";



ALTER INDEX "public"."audit_logs_pkey1" ATTACH PARTITION "public"."audit_logs_2027_08_pkey";



ALTER INDEX "public"."idx_audit_logs_session_id" ATTACH PARTITION "public"."audit_logs_2027_08_session_id_idx";



ALTER INDEX "public"."idx_audit_logs_user_id" ATTACH PARTITION "public"."audit_logs_2027_08_user_id_idx";



ALTER INDEX "public"."idx_audit_logs_action" ATTACH PARTITION "public"."audit_logs_2027_09_action_idx";



ALTER INDEX "public"."audit_logs_pkey1" ATTACH PARTITION "public"."audit_logs_2027_09_pkey";



ALTER INDEX "public"."idx_audit_logs_session_id" ATTACH PARTITION "public"."audit_logs_2027_09_session_id_idx";



ALTER INDEX "public"."idx_audit_logs_user_id" ATTACH PARTITION "public"."audit_logs_2027_09_user_id_idx";



ALTER INDEX "public"."idx_audit_logs_action" ATTACH PARTITION "public"."audit_logs_2027_10_action_idx";



ALTER INDEX "public"."audit_logs_pkey1" ATTACH PARTITION "public"."audit_logs_2027_10_pkey";



ALTER INDEX "public"."idx_audit_logs_session_id" ATTACH PARTITION "public"."audit_logs_2027_10_session_id_idx";



ALTER INDEX "public"."idx_audit_logs_user_id" ATTACH PARTITION "public"."audit_logs_2027_10_user_id_idx";



ALTER INDEX "public"."idx_audit_logs_action" ATTACH PARTITION "public"."audit_logs_2027_11_action_idx";



ALTER INDEX "public"."audit_logs_pkey1" ATTACH PARTITION "public"."audit_logs_2027_11_pkey";



ALTER INDEX "public"."idx_audit_logs_session_id" ATTACH PARTITION "public"."audit_logs_2027_11_session_id_idx";



ALTER INDEX "public"."idx_audit_logs_user_id" ATTACH PARTITION "public"."audit_logs_2027_11_user_id_idx";



ALTER INDEX "public"."idx_audit_logs_action" ATTACH PARTITION "public"."audit_logs_2027_12_action_idx";



ALTER INDEX "public"."audit_logs_pkey1" ATTACH PARTITION "public"."audit_logs_2027_12_pkey";



ALTER INDEX "public"."idx_audit_logs_session_id" ATTACH PARTITION "public"."audit_logs_2027_12_session_id_idx";



ALTER INDEX "public"."idx_audit_logs_user_id" ATTACH PARTITION "public"."audit_logs_2027_12_user_id_idx";



ALTER INDEX "public"."idx_audit_logs_action" ATTACH PARTITION "public"."audit_logs_2028_01_action_idx";



ALTER INDEX "public"."audit_logs_pkey1" ATTACH PARTITION "public"."audit_logs_2028_01_pkey";



ALTER INDEX "public"."idx_audit_logs_session_id" ATTACH PARTITION "public"."audit_logs_2028_01_session_id_idx";



ALTER INDEX "public"."idx_audit_logs_user_id" ATTACH PARTITION "public"."audit_logs_2028_01_user_id_idx";



ALTER INDEX "public"."idx_audit_logs_action" ATTACH PARTITION "public"."audit_logs_2028_02_action_idx";



ALTER INDEX "public"."audit_logs_pkey1" ATTACH PARTITION "public"."audit_logs_2028_02_pkey";



ALTER INDEX "public"."idx_audit_logs_session_id" ATTACH PARTITION "public"."audit_logs_2028_02_session_id_idx";



ALTER INDEX "public"."idx_audit_logs_user_id" ATTACH PARTITION "public"."audit_logs_2028_02_user_id_idx";



ALTER INDEX "public"."idx_audit_logs_action" ATTACH PARTITION "public"."audit_logs_2028_03_action_idx";



ALTER INDEX "public"."audit_logs_pkey1" ATTACH PARTITION "public"."audit_logs_2028_03_pkey";



ALTER INDEX "public"."idx_audit_logs_session_id" ATTACH PARTITION "public"."audit_logs_2028_03_session_id_idx";



ALTER INDEX "public"."idx_audit_logs_user_id" ATTACH PARTITION "public"."audit_logs_2028_03_user_id_idx";



ALTER INDEX "public"."idx_audit_logs_action" ATTACH PARTITION "public"."audit_logs_2028_04_action_idx";



ALTER INDEX "public"."audit_logs_pkey1" ATTACH PARTITION "public"."audit_logs_2028_04_pkey";



ALTER INDEX "public"."idx_audit_logs_session_id" ATTACH PARTITION "public"."audit_logs_2028_04_session_id_idx";



ALTER INDEX "public"."idx_audit_logs_user_id" ATTACH PARTITION "public"."audit_logs_2028_04_user_id_idx";



ALTER INDEX "public"."idx_audit_logs_action" ATTACH PARTITION "public"."audit_logs_2028_05_action_idx";



ALTER INDEX "public"."audit_logs_pkey1" ATTACH PARTITION "public"."audit_logs_2028_05_pkey";



ALTER INDEX "public"."idx_audit_logs_session_id" ATTACH PARTITION "public"."audit_logs_2028_05_session_id_idx";



ALTER INDEX "public"."idx_audit_logs_user_id" ATTACH PARTITION "public"."audit_logs_2028_05_user_id_idx";



ALTER INDEX "public"."idx_audit_logs_action" ATTACH PARTITION "public"."audit_logs_2028_06_action_idx";



ALTER INDEX "public"."audit_logs_pkey1" ATTACH PARTITION "public"."audit_logs_2028_06_pkey";



ALTER INDEX "public"."idx_audit_logs_session_id" ATTACH PARTITION "public"."audit_logs_2028_06_session_id_idx";



ALTER INDEX "public"."idx_audit_logs_user_id" ATTACH PARTITION "public"."audit_logs_2028_06_user_id_idx";



ALTER INDEX "public"."idx_audit_logs_action" ATTACH PARTITION "public"."audit_logs_2028_07_action_idx";



ALTER INDEX "public"."audit_logs_pkey1" ATTACH PARTITION "public"."audit_logs_2028_07_pkey";



ALTER INDEX "public"."idx_audit_logs_session_id" ATTACH PARTITION "public"."audit_logs_2028_07_session_id_idx";



ALTER INDEX "public"."idx_audit_logs_user_id" ATTACH PARTITION "public"."audit_logs_2028_07_user_id_idx";



ALTER INDEX "public"."idx_audit_logs_action" ATTACH PARTITION "public"."audit_logs_2028_08_action_idx";



ALTER INDEX "public"."audit_logs_pkey1" ATTACH PARTITION "public"."audit_logs_2028_08_pkey";



ALTER INDEX "public"."idx_audit_logs_session_id" ATTACH PARTITION "public"."audit_logs_2028_08_session_id_idx";



ALTER INDEX "public"."idx_audit_logs_user_id" ATTACH PARTITION "public"."audit_logs_2028_08_user_id_idx";



ALTER INDEX "public"."idx_audit_logs_action" ATTACH PARTITION "public"."audit_logs_2028_09_action_idx";



ALTER INDEX "public"."audit_logs_pkey1" ATTACH PARTITION "public"."audit_logs_2028_09_pkey";



ALTER INDEX "public"."idx_audit_logs_session_id" ATTACH PARTITION "public"."audit_logs_2028_09_session_id_idx";



ALTER INDEX "public"."idx_audit_logs_user_id" ATTACH PARTITION "public"."audit_logs_2028_09_user_id_idx";



ALTER INDEX "public"."idx_audit_logs_action" ATTACH PARTITION "public"."audit_logs_2028_10_action_idx";



ALTER INDEX "public"."audit_logs_pkey1" ATTACH PARTITION "public"."audit_logs_2028_10_pkey";



ALTER INDEX "public"."idx_audit_logs_session_id" ATTACH PARTITION "public"."audit_logs_2028_10_session_id_idx";



ALTER INDEX "public"."idx_audit_logs_user_id" ATTACH PARTITION "public"."audit_logs_2028_10_user_id_idx";



ALTER INDEX "public"."idx_audit_logs_action" ATTACH PARTITION "public"."audit_logs_2028_11_action_idx";



ALTER INDEX "public"."audit_logs_pkey1" ATTACH PARTITION "public"."audit_logs_2028_11_pkey";



ALTER INDEX "public"."idx_audit_logs_session_id" ATTACH PARTITION "public"."audit_logs_2028_11_session_id_idx";



ALTER INDEX "public"."idx_audit_logs_user_id" ATTACH PARTITION "public"."audit_logs_2028_11_user_id_idx";



ALTER INDEX "public"."idx_audit_logs_action" ATTACH PARTITION "public"."audit_logs_2028_12_action_idx";



ALTER INDEX "public"."audit_logs_pkey1" ATTACH PARTITION "public"."audit_logs_2028_12_pkey";



ALTER INDEX "public"."idx_audit_logs_session_id" ATTACH PARTITION "public"."audit_logs_2028_12_session_id_idx";



ALTER INDEX "public"."idx_audit_logs_user_id" ATTACH PARTITION "public"."audit_logs_2028_12_user_id_idx";



ALTER INDEX "public"."idx_audit_logs_action" ATTACH PARTITION "public"."audit_logs_default_action_idx";



ALTER INDEX "public"."audit_logs_pkey1" ATTACH PARTITION "public"."audit_logs_default_pkey";



ALTER INDEX "public"."idx_audit_logs_session_id" ATTACH PARTITION "public"."audit_logs_default_session_id_idx";



ALTER INDEX "public"."idx_audit_logs_user_id" ATTACH PARTITION "public"."audit_logs_default_user_id_idx";



CREATE OR REPLACE TRIGGER "audit_commissions" AFTER INSERT OR DELETE OR UPDATE ON "public"."commissions" FOR EACH ROW EXECUTE FUNCTION "public"."audit_commissions_trigger"();



CREATE OR REPLACE TRIGGER "check_sensitive_updates" BEFORE UPDATE ON "public"."barbershops" FOR EACH ROW EXECUTE FUNCTION "public"."prevent_sensitive_updates"();



CREATE OR REPLACE TRIGGER "check_subscription_delete" BEFORE DELETE ON "public"."barbershops" FOR EACH ROW EXECUTE FUNCTION "public"."check_subscription_before_delete"();



CREATE CONSTRAINT TRIGGER "enforce_barber_limit" AFTER INSERT OR UPDATE ON "public"."barbers" DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (("new"."is_active" = true)) EXECUTE FUNCTION "public"."check_barber_limit"();



CREATE OR REPLACE TRIGGER "enforce_barber_limit_update" BEFORE UPDATE OF "is_active" ON "public"."barbers" FOR EACH ROW WHEN ((("new"."is_active" = true) AND ("old"."is_active" = false))) EXECUTE FUNCTION "public"."check_barber_limits"();



CREATE OR REPLACE TRIGGER "enforce_mfa_on_barbershop_update" BEFORE UPDATE ON "public"."barbershops" FOR EACH ROW EXECUTE FUNCTION "public"."guard_barbershop_changes"();



CREATE OR REPLACE TRIGGER "ensure_whatsapp_confirmation_trigger" AFTER INSERT ON "public"."appointments_legacy" FOR EACH ROW WHEN (("new"."status" = 'confirmed'::"text")) EXECUTE FUNCTION "public"."ensure_whatsapp_confirmation"();



COMMENT ON TRIGGER "ensure_whatsapp_confirmation_trigger" ON "public"."appointments_legacy" IS 'Garante que nenhum appointment fique sem confirmação WhatsApp via fallback automático.';



CREATE OR REPLACE TRIGGER "handle_updated_at" BEFORE UPDATE ON "public"."barbers" FOR EACH ROW EXECUTE FUNCTION "public"."handle_updated_at"();



CREATE OR REPLACE TRIGGER "handle_updated_at" BEFORE UPDATE ON "public"."barbershops" FOR EACH ROW EXECUTE FUNCTION "public"."handle_updated_at"();



CREATE OR REPLACE TRIGGER "handle_updated_at" BEFORE UPDATE ON "public"."profiles" FOR EACH ROW EXECUTE FUNCTION "public"."handle_updated_at"();



CREATE OR REPLACE TRIGGER "handle_updated_at" BEFORE UPDATE ON "public"."services" FOR EACH ROW EXECUTE FUNCTION "public"."handle_updated_at"();



CREATE OR REPLACE TRIGGER "on_subscription_change_sync_claims" AFTER INSERT OR UPDATE ON "public"."subscriptions" FOR EACH ROW EXECUTE FUNCTION "public"."sync_subscription_to_claims"();



CREATE OR REPLACE TRIGGER "on_suspicious_audit_event" AFTER INSERT ON "public"."sovereign_audit_events" FOR EACH ROW EXECUTE FUNCTION "public"."analyze_threat_events"();



CREATE OR REPLACE TRIGGER "tr_freeze_completed_financials" BEFORE UPDATE ON "public"."appointments_legacy" FOR EACH ROW EXECUTE FUNCTION "public"."freeze_completed_financials"();



CREATE OR REPLACE TRIGGER "tr_protect_user_roles" BEFORE INSERT OR DELETE OR UPDATE ON "public"."user_roles" FOR EACH ROW EXECUTE FUNCTION "public"."prevent_role_escalation"();



CREATE OR REPLACE TRIGGER "tr_sync_financial" AFTER INSERT OR UPDATE ON "public"."appointments" FOR EACH ROW EXECUTE FUNCTION "public"."sync_financial_from_appointments"();



CREATE OR REPLACE TRIGGER "tr_sync_user_roles" AFTER INSERT OR UPDATE ON "public"."user_roles" FOR EACH ROW EXECUTE FUNCTION "public"."sync_user_roles_to_app_metadata"();



CREATE OR REPLACE TRIGGER "trg_audit_barbers_commission" AFTER UPDATE ON "public"."barbers" FOR EACH ROW EXECUTE FUNCTION "public"."audit_barbers_commission_changes"();



CREATE OR REPLACE TRIGGER "trg_audit_barbershop_status" AFTER UPDATE ON "public"."barbershops" FOR EACH ROW EXECUTE FUNCTION "public"."audit_barbershop_status_changes"();



CREATE OR REPLACE TRIGGER "trg_audit_logs_default_immutable" BEFORE DELETE OR UPDATE ON "public"."audit_logs_default" FOR EACH ROW EXECUTE FUNCTION "public"."guard_audit_logs_immutability"();



CREATE OR REPLACE TRIGGER "trg_audit_logs_immutable" BEFORE DELETE OR UPDATE ON "public"."audit_logs" FOR EACH ROW EXECUTE FUNCTION "public"."guard_audit_logs_immutability"();



CREATE OR REPLACE TRIGGER "trg_audit_logs_immutable" BEFORE DELETE OR UPDATE ON "public"."sovereign_audit_events" FOR EACH ROW EXECUTE FUNCTION "public"."prevent_log_manipulation"();



CREATE OR REPLACE TRIGGER "trg_audit_services_financial" AFTER UPDATE ON "public"."services" FOR EACH ROW EXECUTE FUNCTION "public"."audit_services_financial_changes"();



CREATE OR REPLACE TRIGGER "trg_audit_user_roles" AFTER INSERT OR DELETE OR UPDATE ON "public"."user_roles" FOR EACH ROW EXECUTE FUNCTION "public"."audit_user_roles_changes"();



CREATE OR REPLACE TRIGGER "trg_auto_track_barber_added" AFTER INSERT ON "public"."barbers" FOR EACH ROW EXECUTE FUNCTION "public"."auto_track_barber_added"();



CREATE OR REPLACE TRIGGER "trg_auto_track_service_added" AFTER INSERT ON "public"."services" FOR EACH ROW EXECUTE FUNCTION "public"."auto_track_service_added"();



CREATE OR REPLACE TRIGGER "trg_buffer_bi_events" AFTER INSERT OR UPDATE ON "public"."appointments_legacy" FOR EACH ROW EXECUTE FUNCTION "public"."buffer_bi_event"();



CREATE OR REPLACE TRIGGER "trg_calculate_commission" AFTER UPDATE ON "public"."appointments" FOR EACH ROW EXECUTE FUNCTION "public"."trigger_calculate_commission"();



CREATE OR REPLACE TRIGGER "trg_clean_appointment_notes" BEFORE INSERT OR UPDATE ON "public"."appointments" FOR EACH ROW EXECUTE FUNCTION "public"."clean_metadata_input"();



CREATE OR REPLACE TRIGGER "trg_clean_customer_name" BEFORE INSERT OR UPDATE ON "public"."customers" FOR EACH ROW EXECUTE FUNCTION "public"."clean_metadata_input"();



CREATE OR REPLACE TRIGGER "trg_prevent_barber_delete" BEFORE DELETE ON "public"."barbers" FOR EACH ROW EXECUTE FUNCTION "public"."prevent_barber_hard_delete"();



CREATE OR REPLACE TRIGGER "trg_prevent_service_delete" BEFORE DELETE ON "public"."services" FOR EACH ROW EXECUTE FUNCTION "public"."prevent_service_hard_delete"();



CREATE OR REPLACE TRIGGER "trg_sanitize_audit_logs" BEFORE INSERT OR UPDATE ON "public"."audit_logs" FOR EACH ROW EXECUTE FUNCTION "public"."sanitize_xss_trigger"();



CREATE OR REPLACE TRIGGER "trg_set_time_and_duration" BEFORE INSERT OR UPDATE ON "public"."appointments_legacy" FOR EACH ROW EXECUTE FUNCTION "public"."set_time_and_duration"();



CREATE OR REPLACE TRIGGER "trg_warn_default_partition" BEFORE INSERT ON "public"."audit_logs_default" FOR EACH ROW EXECUTE FUNCTION "public"."warn_default_partition_insert"();



CREATE OR REPLACE TRIGGER "trigger_validate_whatsapp_cooldown" BEFORE INSERT ON "public"."whatsapp_logs" FOR EACH ROW EXECUTE FUNCTION "public"."validate_whatsapp_cooldown"();



COMMENT ON TRIGGER "trigger_validate_whatsapp_cooldown" ON "public"."whatsapp_logs" IS 'Garante atomicidade na verificação de cooldown antes de inserir logs WhatsApp.';



CREATE OR REPLACE TRIGGER "update_appointments_modtime" BEFORE UPDATE ON "public"."appointments_legacy" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "update_barbers_modtime" BEFORE UPDATE ON "public"."barbers" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "update_barbershops_modtime" BEFORE UPDATE ON "public"."barbershops" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "update_customers_modtime" BEFORE UPDATE ON "public"."customers" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "update_products_modtime" BEFORE UPDATE ON "public"."products" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "update_rate_limits_modtime" BEFORE UPDATE ON "public"."rate_limits" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "update_services_modtime" BEFORE UPDATE ON "public"."services" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "update_subscription_overrides_updated_at" BEFORE UPDATE ON "public"."subscription_overrides" FOR EACH ROW EXECUTE FUNCTION "public"."update_subscription_overrides_updated_at"();



CREATE OR REPLACE TRIGGER "update_whatsapp_retry_queue_modtime" BEFORE UPDATE ON "public"."whatsapp_retry_queue" FOR EACH ROW EXECUTE FUNCTION "public"."update_updated_at_column"();



CREATE OR REPLACE TRIGGER "update_whatsapp_retry_queue_updated_at" BEFORE UPDATE ON "public"."whatsapp_retry_queue" FOR EACH ROW EXECUTE FUNCTION "public"."update_whatsapp_retry_queue_updated_at"();



ALTER TABLE ONLY "public"."appointment_cancellations"
    ADD CONSTRAINT "appointment_cancellations_appointment_id_fkey" FOREIGN KEY ("appointment_id") REFERENCES "public"."appointments_legacy"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."appointment_tokens"
    ADD CONSTRAINT "appointment_tokens_appointment_id_fkey" FOREIGN KEY ("appointment_id") REFERENCES "public"."appointments_legacy"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."appointments_legacy"
    ADD CONSTRAINT "appointments_barber_id_fkey" FOREIGN KEY ("barber_id") REFERENCES "public"."barbers"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."appointments_legacy"
    ADD CONSTRAINT "appointments_barbershop_id_fkey" FOREIGN KEY ("barbershop_id") REFERENCES "public"."barbershops"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."appointments_legacy"
    ADD CONSTRAINT "appointments_customer_id_fkey" FOREIGN KEY ("customer_id") REFERENCES "public"."customers"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."appointments_legacy"
    ADD CONSTRAINT "appointments_service_id_fkey" FOREIGN KEY ("service_id") REFERENCES "public"."services"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."backup_codes"
    ADD CONSTRAINT "backup_codes_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."barbers"
    ADD CONSTRAINT "barbers_barbershop_id_fkey" FOREIGN KEY ("barbershop_id") REFERENCES "public"."barbershops"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."barbers"
    ADD CONSTRAINT "barbers_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."barbershop_expenses"
    ADD CONSTRAINT "barbershop_expenses_barbershop_id_fkey" FOREIGN KEY ("barbershop_id") REFERENCES "public"."barbershops"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."barbershop_expenses"
    ADD CONSTRAINT "barbershop_expenses_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "auth"."users"("id");



ALTER TABLE ONLY "public"."barbershops"
    ADD CONSTRAINT "barbershops_owner_id_fkey" FOREIGN KEY ("owner_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."bi_log"
    ADD CONSTRAINT "bi_log_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "public"."barbershops"("id");



ALTER TABLE ONLY "public"."commission_settings"
    ADD CONSTRAINT "commission_settings_barber_id_fkey" FOREIGN KEY ("barber_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."commission_settings"
    ADD CONSTRAINT "commission_settings_barbershop_id_fkey" FOREIGN KEY ("barbershop_id") REFERENCES "public"."barbershops"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."commission_settings"
    ADD CONSTRAINT "commission_settings_service_id_fkey" FOREIGN KEY ("service_id") REFERENCES "public"."services"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."commissions"
    ADD CONSTRAINT "commissions_appointment_id_fkey" FOREIGN KEY ("appointment_id") REFERENCES "public"."appointments_legacy"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."commissions"
    ADD CONSTRAINT "commissions_barber_id_fkey" FOREIGN KEY ("barber_id") REFERENCES "public"."barbers"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."commissions"
    ADD CONSTRAINT "commissions_barbershop_id_fkey" FOREIGN KEY ("barbershop_id") REFERENCES "public"."barbershops"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."commissions"
    ADD CONSTRAINT "commissions_sale_id_fkey" FOREIGN KEY ("sale_id") REFERENCES "public"."sales"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."csp_violations"
    ADD CONSTRAINT "csp_violations_barbershop_id_fkey" FOREIGN KEY ("barbershop_id") REFERENCES "public"."barbershops"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."customer_magic_links"
    ADD CONSTRAINT "customer_magic_links_customer_id_fkey" FOREIGN KEY ("customer_id") REFERENCES "public"."customers"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."customers"
    ADD CONSTRAINT "customers_barbershop_id_fkey" FOREIGN KEY ("barbershop_id") REFERENCES "public"."barbershops"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."customers"
    ADD CONSTRAINT "customers_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."daily_metrics"
    ADD CONSTRAINT "daily_metrics_barbershop_id_fkey" FOREIGN KEY ("barbershop_id") REFERENCES "public"."barbershops"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."expenses"
    ADD CONSTRAINT "expenses_barbershop_id_fkey" FOREIGN KEY ("barbershop_id") REFERENCES "public"."barbershops"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."financial_ledger"
    ADD CONSTRAINT "financial_ledger_appointment_id_appointment_date_fkey" FOREIGN KEY ("appointment_id", "appointment_date") REFERENCES "public"."appointments"("id", "appointment_date") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."financial_ledger"
    ADD CONSTRAINT "financial_ledger_barber_id_fkey" FOREIGN KEY ("barber_id") REFERENCES "public"."profiles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."financial_ledger"
    ADD CONSTRAINT "financial_ledger_barbershop_id_fkey" FOREIGN KEY ("barbershop_id") REFERENCES "public"."barbershops"("id") ON DELETE CASCADE;



ALTER TABLE "public"."appointments"
    ADD CONSTRAINT "fk_appointments_barber" FOREIGN KEY ("barber_id") REFERENCES "public"."barbers"("id");



ALTER TABLE "public"."appointments"
    ADD CONSTRAINT "fk_appointments_barbershop" FOREIGN KEY ("barbershop_id") REFERENCES "public"."barbershops"("id");



ALTER TABLE "public"."appointments"
    ADD CONSTRAINT "fk_appointments_customer" FOREIGN KEY ("customer_id") REFERENCES "public"."customers"("id");



ALTER TABLE "public"."appointments"
    ADD CONSTRAINT "fk_appointments_service" FOREIGN KEY ("service_id") REFERENCES "public"."services"("id");



ALTER TABLE ONLY "public"."loyalty_points"
    ADD CONSTRAINT "loyalty_points_barbershop_id_fkey" FOREIGN KEY ("barbershop_id") REFERENCES "public"."barbershops"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."loyalty_points"
    ADD CONSTRAINT "loyalty_points_customer_id_fkey" FOREIGN KEY ("customer_id") REFERENCES "public"."customers"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."mfa_recovery_attempts"
    ADD CONSTRAINT "mfa_recovery_attempts_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."notification_queue"
    ADD CONSTRAINT "notification_queue_appointment_id_fkey" FOREIGN KEY ("appointment_id") REFERENCES "public"."appointments_legacy"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."permission_audit_log"
    ADD CONSTRAINT "permission_audit_log_target_user_id_fkey" FOREIGN KEY ("target_user_id") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."permission_audit_log"
    ADD CONSTRAINT "permission_audit_log_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."products"
    ADD CONSTRAINT "products_barbershop_id_fkey" FOREIGN KEY ("barbershop_id") REFERENCES "public"."barbershops"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."profiles"
    ADD CONSTRAINT "profiles_id_fkey" FOREIGN KEY ("id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."salary_expenses"
    ADD CONSTRAINT "salary_expenses_barber_id_fkey" FOREIGN KEY ("barber_id") REFERENCES "public"."barbers"("id");



ALTER TABLE ONLY "public"."salary_expenses"
    ADD CONSTRAINT "salary_expenses_barbershop_id_fkey" FOREIGN KEY ("barbershop_id") REFERENCES "public"."barbershops"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."sale_items"
    ADD CONSTRAINT "sale_items_product_id_fkey" FOREIGN KEY ("product_id") REFERENCES "public"."products"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."sale_items"
    ADD CONSTRAINT "sale_items_sale_id_fkey" FOREIGN KEY ("sale_id") REFERENCES "public"."sales"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."sales"
    ADD CONSTRAINT "sales_appointment_id_fkey" FOREIGN KEY ("appointment_id") REFERENCES "public"."appointments_legacy"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."sales"
    ADD CONSTRAINT "sales_barber_id_fkey" FOREIGN KEY ("barber_id") REFERENCES "public"."barbers"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."sales"
    ADD CONSTRAINT "sales_barbershop_id_fkey" FOREIGN KEY ("barbershop_id") REFERENCES "public"."barbershops"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."sales"
    ADD CONSTRAINT "sales_customer_id_fkey" FOREIGN KEY ("customer_id") REFERENCES "public"."customers"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."security_events"
    ADD CONSTRAINT "security_events_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."services"
    ADD CONSTRAINT "services_barbershop_id_fkey" FOREIGN KEY ("barbershop_id") REFERENCES "public"."barbershops"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."sovereign_audit_events"
    ADD CONSTRAINT "sovereign_audit_events_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."subscription_logs"
    ADD CONSTRAINT "subscription_logs_barbershop_id_fkey" FOREIGN KEY ("barbershop_id") REFERENCES "public"."barbershops"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."subscriptions"
    ADD CONSTRAINT "subscriptions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id");



ALTER TABLE ONLY "public"."user_events"
    ADD CONSTRAINT "user_events_barbershop_id_fkey" FOREIGN KEY ("barbershop_id") REFERENCES "public"."barbershops"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."user_roles"
    ADD CONSTRAINT "user_roles_barbershop_id_fkey" FOREIGN KEY ("barbershop_id") REFERENCES "public"."barbershops"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."user_roles"
    ADD CONSTRAINT "user_roles_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."user_security_profiles"
    ADD CONSTRAINT "user_security_profiles_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."whatsapp_logs"
    ADD CONSTRAINT "whatsapp_logs_appointment_id_fkey" FOREIGN KEY ("appointment_id") REFERENCES "public"."appointments_legacy"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."whatsapp_logs"
    ADD CONSTRAINT "whatsapp_logs_barbershop_id_fkey" FOREIGN KEY ("barbershop_id") REFERENCES "public"."barbershops"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."whatsapp_retry_queue"
    ADD CONSTRAINT "whatsapp_retry_queue_appointment_id_fkey" FOREIGN KEY ("appointment_id") REFERENCES "public"."appointments_legacy"("id") ON DELETE CASCADE;



CREATE POLICY "Admin can view health logs" ON "public"."cron_health_logs" FOR SELECT USING ((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE ("barbershops"."owner_id" = "auth"."uid"()))));



CREATE POLICY "Admins Manage Settings" ON "public"."system_settings" TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."profiles"
  WHERE (("profiles"."id" = "auth"."uid"()) AND ("profiles"."role" = 'admin'::"text")))));



CREATE POLICY "Admins can view csp violations" ON "public"."csp_violations" FOR SELECT USING (("auth"."role"() = 'service_role'::"text"));



CREATE POLICY "Admins can view login logs" ON "public"."login_attempts" FOR SELECT TO "service_role" USING (true);



CREATE POLICY "Admins can view whatsapp logs" ON "public"."whatsapp_logs" FOR SELECT TO "service_role" USING (true);



CREATE POLICY "Anon view public barbershops" ON "public"."barbershops" FOR SELECT TO "anon" USING ((("subscription_status" <> 'cancelled'::"text") AND ("deleted_at" IS NULL)));



CREATE POLICY "Authenticated staff view barbers" ON "public"."barbers" FOR SELECT TO "authenticated" USING (((EXISTS ( SELECT 1
   FROM "public"."user_roles"
  WHERE (("user_roles"."user_id" = "auth"."uid"()) AND ("user_roles"."barbershop_id" = "barbers"."barbershop_id")))) OR ("user_id" = "auth"."uid"())));



CREATE POLICY "Authenticated view active barbers" ON "public"."barbers" FOR SELECT TO "authenticated" USING (((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "barbers"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"())))) OR ("user_id" = "auth"."uid"()) OR (("is_active" = true) AND (EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "barbers"."barbershop_id") AND ("barbershops"."subscription_status" <> 'cancelled'::"text")))))));



CREATE POLICY "Authenticated view active barbershops" ON "public"."barbershops" FOR SELECT TO "authenticated" USING ((("subscription_status" <> 'cancelled'::"text") OR ("auth"."uid"() = "owner_id")));



CREATE POLICY "Barbers can view own commissions" ON "public"."commissions" FOR SELECT USING (("barber_id" IN ( SELECT "barbers"."id"
   FROM "public"."barbers"
  WHERE ("barbers"."user_id" = "auth"."uid"()))));



CREATE POLICY "Barbers can view their own commissions" ON "public"."commissions" FOR SELECT USING ((EXISTS ( SELECT 1
   FROM "public"."barbers"
  WHERE (("barbers"."id" = "commissions"."barber_id") AND ("barbers"."user_id" = "auth"."uid"())))));



CREATE POLICY "Barbers manage own appointments" ON "public"."appointments_legacy" USING ((("auth"."role"() = 'authenticated'::"text") AND (EXISTS ( SELECT 1
   FROM "public"."barbers"
  WHERE (("barbers"."id" = "appointments_legacy"."barber_id") AND ("barbers"."user_id" = "auth"."uid"()))))));



CREATE POLICY "Barbers update own profile" ON "public"."barbers" FOR UPDATE TO "authenticated" USING (("auth"."uid"() = "user_id")) WITH CHECK (("auth"."uid"() = "user_id"));



CREATE POLICY "Barbers view own profile" ON "public"."barbers" FOR SELECT USING ((("auth"."role"() = 'authenticated'::"text") AND (("user_id" = "auth"."uid"()) OR (EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "barbers"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"())))))));



CREATE POLICY "Barbershop owners can delete their CSP violations" ON "public"."csp_violations" FOR DELETE USING ((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "csp_violations"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"())))));



CREATE POLICY "Barbershop owners can manage commissions" ON "public"."commissions" USING ((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "commissions"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"())))));



CREATE POLICY "Barbershop owners can manage products" ON "public"."products" USING ((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "products"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"())))));



CREATE POLICY "Barbershop owners can manage sale items" ON "public"."sale_items" USING ((EXISTS ( SELECT 1
   FROM ("public"."sales"
     JOIN "public"."barbershops" ON (("barbershops"."id" = "sales"."barbershop_id")))
  WHERE (("sales"."id" = "sale_items"."sale_id") AND ("barbershops"."owner_id" = "auth"."uid"())))));



CREATE POLICY "Barbershop owners can manage sales" ON "public"."sales" USING ((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "sales"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"())))));



CREATE POLICY "Barbershop owners can manage their loyalty points" ON "public"."loyalty_points" USING ((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "loyalty_points"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"())))));



CREATE POLICY "Barbershop owners can update loyalty points" ON "public"."loyalty_points" FOR UPDATE USING ((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "loyalty_points"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"())))));



CREATE POLICY "Barbershop owners can view cancellations" ON "public"."appointment_cancellations" FOR SELECT USING ((EXISTS ( SELECT 1
   FROM ("public"."appointments_legacy" "a"
     JOIN "public"."barbershops" "b" ON (("a"."barbershop_id" = "b"."id")))
  WHERE (("a"."id" = "appointment_cancellations"."appointment_id") AND ("b"."owner_id" = "auth"."uid"())))));



CREATE POLICY "Barbershop owners can view subscription logs" ON "public"."subscription_logs" FOR SELECT USING ((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "subscription_logs"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"())))));



CREATE POLICY "Barbershop owners can view their CSP violations" ON "public"."csp_violations" FOR SELECT USING ((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "csp_violations"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"())))));



CREATE POLICY "Barbershop owners can view their loyalty points" ON "public"."loyalty_points" FOR SELECT USING ((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "loyalty_points"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"())))));



CREATE POLICY "Barbershop owners can view whatsapp logs" ON "public"."whatsapp_logs" FOR SELECT USING ((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "whatsapp_logs"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"())))));



CREATE POLICY "Barbershop owners view staff/customers profiles" ON "public"."profiles" FOR SELECT TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM ("public"."user_roles" "my_staff"
     JOIN "public"."user_roles" "target_roles" ON (("my_staff"."barbershop_id" = "target_roles"."barbershop_id")))
  WHERE (("my_staff"."user_id" = "auth"."uid"()) AND ("my_staff"."role" = 'owner'::"public"."app_role") AND ("target_roles"."user_id" = "profiles"."id")))));



CREATE POLICY "Barbershops access via security definer" ON "public"."barbershops" FOR SELECT USING ((("auth"."uid"() = "owner_id") OR "public"."has_barbershop_role"("auth"."uid"(), "id", 'barber'::"public"."app_role") OR "public"."has_barbershop_role"("auth"."uid"(), "id", 'customer'::"public"."app_role") OR (("subscription_status" <> 'cancelled'::"text") AND ("auth"."uid"() IS NULL))));



CREATE POLICY "Block anon select from retry queue" ON "public"."whatsapp_retry_queue" FOR SELECT TO "anon" USING (false);



CREATE POLICY "Block public access to rate limits" ON "public"."rate_limits" FOR SELECT TO "authenticated", "anon" USING (false);



CREATE POLICY "Block public delete to rate limits" ON "public"."rate_limits" FOR DELETE TO "authenticated", "anon" USING (false);



CREATE POLICY "Block public insert to rate limits" ON "public"."rate_limits" FOR INSERT TO "authenticated", "anon" WITH CHECK (false);



CREATE POLICY "Block public update to rate limits" ON "public"."rate_limits" FOR UPDATE TO "authenticated", "anon" USING (false) WITH CHECK (false);



CREATE POLICY "Block user delete to retry queue" ON "public"."whatsapp_retry_queue" FOR DELETE TO "authenticated", "anon" USING (false);



CREATE POLICY "Block user insert to retry queue" ON "public"."whatsapp_retry_queue" FOR INSERT TO "authenticated", "anon" WITH CHECK (false);



CREATE POLICY "Block user update to retry queue" ON "public"."whatsapp_retry_queue" FOR UPDATE TO "authenticated", "anon" USING (false) WITH CHECK (false);



CREATE POLICY "Controlled insert appointments" ON "public"."appointments_legacy" FOR INSERT WITH CHECK ((("auth"."role"() = 'anon'::"text") OR (("auth"."role"() = 'authenticated'::"text") AND (EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "appointments_legacy"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"()) AND ("barbershops"."subscription_status" = 'active'::"text")))))));



COMMENT ON POLICY "Controlled insert appointments" ON "public"."appointments_legacy" IS 'Security: Anon allow (public). Auth allow ONLY if Owner AND Active Subscription.';



CREATE POLICY "No one can delete whatsapp logs" ON "public"."whatsapp_logs" FOR DELETE TO "authenticated" USING (false);



CREATE POLICY "No one can update CSP violations" ON "public"."csp_violations" FOR UPDATE USING (false);



CREATE POLICY "No one can update whatsapp logs" ON "public"."whatsapp_logs" FOR UPDATE TO "authenticated" USING (false);



CREATE POLICY "Owner Modify Barbers" ON "public"."barbers" TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."barbershops" "b"
  WHERE (("b"."id" = "barbers"."barbershop_id") AND ("b"."owner_id" = "auth"."uid"()))))) WITH CHECK ((EXISTS ( SELECT 1
   FROM "public"."barbershops" "b"
  WHERE (("b"."id" = "barbers"."barbershop_id") AND ("b"."owner_id" = "auth"."uid"())))));



CREATE POLICY "Owner Modify Barbershops" ON "public"."barbershops" TO "authenticated" USING (("owner_id" = "auth"."uid"())) WITH CHECK (("owner_id" = "auth"."uid"()));



CREATE POLICY "Owner Modify Services" ON "public"."services" TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."barbershops" "b"
  WHERE (("b"."id" = "services"."barbershop_id") AND ("b"."owner_id" = "auth"."uid"()))))) WITH CHECK ((EXISTS ( SELECT 1
   FROM "public"."barbershops" "b"
  WHERE (("b"."id" = "services"."barbershop_id") AND ("b"."owner_id" = "auth"."uid"())))));



CREATE POLICY "Owner can view own barbers" ON "public"."barbers" FOR SELECT USING ((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "barbers"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"())))));



CREATE POLICY "Owner can view own barbershop" ON "public"."barbershops" FOR SELECT USING (("auth"."uid"() = "owner_id"));



CREATE POLICY "Owner can view own services" ON "public"."services" FOR SELECT USING ((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "services"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"())))));



CREATE POLICY "Owners Edit Expenses (Active Sub + MFA)" ON "public"."expenses" USING ((("auth"."uid"() IN ( SELECT "barbershops"."owner_id"
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "expenses"."barbershop_id") AND ("barbershops"."subscription_status" = ANY (ARRAY['active'::"text", 'trialing'::"text"]))))) AND ("public"."check_mfa_compliance"() = true)));



CREATE POLICY "Owners View Expenses (MFA)" ON "public"."expenses" FOR SELECT USING ((("auth"."uid"() IN ( SELECT "barbershops"."owner_id"
   FROM "public"."barbershops"
  WHERE ("barbershops"."id" = "expenses"."barbershop_id"))) AND ("public"."check_mfa_compliance"() = true)));



COMMENT ON POLICY "Owners View Expenses (MFA)" ON "public"."expenses" IS 'Protegido por MFA';



CREATE POLICY "Owners View Salaries (MFA)" ON "public"."salary_expenses" FOR SELECT USING ((("auth"."uid"() IN ( SELECT "barbershops"."owner_id"
   FROM "public"."barbershops"
  WHERE ("barbershops"."id" = "salary_expenses"."barbershop_id"))) AND ("public"."check_mfa_compliance"() = true)));



CREATE POLICY "Owners can manage their customers" ON "public"."customers" TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "customers"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"()))))) WITH CHECK ((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "customers"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"())))));



COMMENT ON POLICY "Owners can manage their customers" ON "public"."customers" IS 'Permite que donos de barbearia gerenciem apenas seus próprios clientes.';



CREATE POLICY "Owners can view appointment of their barbershop" ON "public"."appointments_legacy" FOR SELECT TO "authenticated" USING (("barbershop_id" IN ( SELECT "barbershops"."id"
   FROM "public"."barbershops"
  WHERE ("barbershops"."owner_id" = "auth"."uid"()))));



CREATE POLICY "Owners can view barbers of their barbershop" ON "public"."barbers" FOR SELECT TO "authenticated" USING (("barbershop_id" IN ( SELECT "barbershops"."id"
   FROM "public"."barbershops"
  WHERE ("barbershops"."owner_id" = "auth"."uid"()))));



CREATE POLICY "Owners can view barbershop events" ON "public"."user_events" FOR SELECT USING (("barbershop_id" IN ( SELECT "barbershops"."id"
   FROM "public"."barbershops"
  WHERE ("barbershops"."owner_id" = "auth"."uid"()))));



CREATE POLICY "Owners can view commissions" ON "public"."commissions" FOR SELECT USING ((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "commissions"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"())))));



CREATE POLICY "Owners can view customers of their barbershop" ON "public"."customers" FOR SELECT TO "authenticated" USING (("barbershop_id" IN ( SELECT "barbershops"."id"
   FROM "public"."barbershops"
  WHERE ("barbershops"."owner_id" = "auth"."uid"()))));



CREATE POLICY "Owners can view own barbershop" ON "public"."barbershops" FOR SELECT TO "authenticated" USING (("owner_id" = "auth"."uid"()));



CREATE POLICY "Owners can view services of their barbershop" ON "public"."services" FOR SELECT TO "authenticated" USING (("barbershop_id" IN ( SELECT "barbershops"."id"
   FROM "public"."barbershops"
  WHERE ("barbershops"."owner_id" = "auth"."uid"()))));



CREATE POLICY "Owners can view their retry queue" ON "public"."whatsapp_retry_queue" FOR SELECT TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM ("public"."appointments_legacy" "a"
     JOIN "public"."barbershops" "b" ON (("a"."barbershop_id" = "b"."id")))
  WHERE (("a"."id" = "whatsapp_retry_queue"."appointment_id") AND ("b"."owner_id" = "auth"."uid"())))));



CREATE POLICY "Owners delete barbers (Active Sub)" ON "public"."barbers" FOR DELETE USING ((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "barbers"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"()) AND ("barbershops"."subscription_status" = ANY (ARRAY['active'::"text", 'trialing'::"text"]))))));



CREATE POLICY "Owners delete services (Active Sub)" ON "public"."services" FOR DELETE USING ((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "services"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"()) AND ("barbershops"."subscription_status" = ANY (ARRAY['active'::"text", 'trialing'::"text"]))))));



CREATE POLICY "Owners manage appointments" ON "public"."appointments_legacy" USING ((("auth"."role"() = 'authenticated'::"text") AND (EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "appointments_legacy"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"()))))));



CREATE POLICY "Owners manage barbers" ON "public"."barbers" USING ((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "barbers"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"())))));



CREATE POLICY "Owners manage customers" ON "public"."customers" USING ((("auth"."role"() = 'authenticated'::"text") AND (EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "customers"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"()))))));



CREATE POLICY "Owners manage own barbershop" ON "public"."barbershops" USING (("auth"."uid"() = "owner_id"));



CREATE POLICY "Owners manage services" ON "public"."services" USING ((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "services"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"())))));



CREATE POLICY "Owners search own daily_metrics" ON "public"."daily_metrics" FOR SELECT TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "daily_metrics"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"())))));



CREATE POLICY "Owners update barbers (Active Sub)" ON "public"."barbers" FOR UPDATE USING ((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "barbers"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"()) AND ("barbershops"."subscription_status" = ANY (ARRAY['active'::"text", 'trialing'::"text"]))))));



CREATE POLICY "Owners update own barbershop" ON "public"."barbershops" FOR UPDATE USING (("owner_id" = "auth"."uid"())) WITH CHECK ((("owner_id" = "auth"."uid"()) AND ("subscription_status" = ANY (ARRAY['active'::"text", 'trialing'::"text"]))));



CREATE POLICY "Owners update services (Active Sub)" ON "public"."services" FOR UPDATE USING ((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "services"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"()) AND ("barbershops"."subscription_status" = ANY (ARRAY['active'::"text", 'trialing'::"text"]))))));



CREATE POLICY "Owners view appointments" ON "public"."appointments_legacy" FOR SELECT USING ((("auth"."role"() = 'authenticated'::"text") AND (EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "appointments_legacy"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"()))))));



CREATE POLICY "Owners view customers" ON "public"."customers" FOR SELECT USING ((("auth"."role"() = 'authenticated'::"text") AND (EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "customers"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"()))))));



CREATE POLICY "Owners write barbers (Active Sub)" ON "public"."barbers" FOR INSERT WITH CHECK ((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "barbers"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"()) AND ("barbershops"."subscription_status" = ANY (ARRAY['active'::"text", 'trialing'::"text"]))))));



CREATE POLICY "Owners write services (Active Sub)" ON "public"."services" FOR INSERT WITH CHECK ((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "services"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"()) AND ("barbershops"."subscription_status" = ANY (ARRAY['active'::"text", 'trialing'::"text"]))))));



CREATE POLICY "Premium or trial required for products" ON "public"."products" USING ((EXISTS ( SELECT 1
   FROM "public"."barbershops" "b"
  WHERE (("b"."id" = "products"."barbershop_id") AND (("b"."subscription_plan" = 'premium'::"text") OR (("b"."trial_ends_at" IS NOT NULL) AND ("b"."trial_ends_at" > "now"())))))));



CREATE POLICY "Profiles self-read" ON "public"."profiles" FOR SELECT TO "authenticated" USING (("auth"."uid"() = "id"));



CREATE POLICY "Public Read Reasons" ON "public"."cancel_reasons" FOR SELECT TO "authenticated", "anon" USING (true);



CREATE POLICY "Public Read Services" ON "public"."services" FOR SELECT USING (true);



CREATE POLICY "Public anonymous view active barbers" ON "public"."barbers" FOR SELECT TO "anon" USING (("is_active" = true));



CREATE POLICY "Public can view active barbers via secure view only" ON "public"."barbers" FOR SELECT TO "anon" USING (false);



COMMENT ON POLICY "Public can view active barbers via secure view only" ON "public"."barbers" IS 'Segurança: Anon não acessa tabela diretamente. Usar view public_barbers_secure.';



CREATE POLICY "Public can view active services" ON "public"."services" FOR SELECT TO "authenticated", "anon" USING (("is_active" = true));



CREATE POLICY "Public read plans" ON "public"."plans" FOR SELECT USING (true);



CREATE POLICY "Public read services" ON "public"."services" FOR SELECT USING (true);



CREATE POLICY "Rate limits are private" ON "public"."rate_limits" TO "service_role" USING (true) WITH CHECK (true);



CREATE POLICY "Secure legacy appointment creation" ON "public"."appointments_legacy" FOR INSERT TO "authenticated" WITH CHECK ((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "appointments_legacy"."barbershop_id") AND ("barbershops"."subscription_status" = 'active'::"text") AND ("barbershops"."deleted_at" IS NULL)))));



CREATE POLICY "Service Role Full Access" ON "public"."login_attempts" TO "service_role" USING (true) WITH CHECK (true);



CREATE POLICY "Service Role Full Access" ON "public"."rate_limits" TO "service_role" USING (true) WITH CHECK (true);



CREATE POLICY "Service Role Full Access" ON "public"."security_events" TO "service_role" USING (true) WITH CHECK (true);



CREATE POLICY "Service Role Full Access" ON "public"."sovereign_audit_events" TO "service_role" USING (true) WITH CHECK (true);



CREATE POLICY "Service Role Full Access" ON "public"."whatsapp_logs" TO "service_role" USING (true) WITH CHECK (true);



CREATE POLICY "Service Role Only" ON "public"."_sovereign_audit_log" TO "service_role" USING (true) WITH CHECK (true);



CREATE POLICY "Service Role can manage all" ON "public"."user_security_profiles" TO "service_role" USING (true);



CREATE POLICY "Service role can insert cancellations" ON "public"."appointment_cancellations" FOR INSERT WITH CHECK (true);



CREATE POLICY "Service role can insert events" ON "public"."user_events" FOR INSERT WITH CHECK (true);



CREATE POLICY "Service role can insert whatsapp logs" ON "public"."whatsapp_logs" FOR INSERT TO "service_role" WITH CHECK (true);



CREATE POLICY "Service role can manage retention logs" ON "public"."data_retention_log" USING (("auth"."role"() = 'service_role'::"text"));



CREATE POLICY "Service role can manage security events" ON "public"."security_events" USING (("auth"."role"() = 'service_role'::"text"));



CREATE POLICY "Service role full access" ON "public"."appointment_tokens" TO "service_role" USING (true) WITH CHECK (true);



CREATE POLICY "Service role full access" ON "public"."customers" TO "service_role" USING (true) WITH CHECK (true);



CREATE POLICY "Service role pode inserir tokens" ON "public"."appointment_tokens" FOR INSERT WITH CHECK (true);



CREATE POLICY "Sovereign Barber View Commissions" ON "public"."commission_settings" FOR SELECT TO "authenticated" USING ((("barber_id" IN ( SELECT "barbers"."id"
   FROM "public"."barbers"
  WHERE ("barbers"."user_id" = "auth"."uid"()))) OR (("rule_type" = 'global'::"public"."commission_rule_type") AND (EXISTS ( SELECT 1
   FROM "public"."barbers"
  WHERE (("barbers"."barbershop_id" = "commission_settings"."barbershop_id") AND ("barbers"."user_id" = "auth"."uid"())))))));



CREATE POLICY "Sovereign Barber View Own Ledger" ON "public"."financial_ledger" FOR SELECT TO "authenticated" USING (("barber_id" IN ( SELECT "barbers"."id"
   FROM "public"."barbers"
  WHERE ("barbers"."user_id" = "auth"."uid"()))));



CREATE POLICY "Sovereign Customer Read Appointments" ON "public"."appointments" FOR SELECT TO "authenticated" USING (("customer_id" IN ( SELECT "customers"."id"
   FROM "public"."customers"
  WHERE ("customers"."user_id" = "auth"."uid"()))));



CREATE POLICY "Sovereign Customer Self View" ON "public"."customers" FOR SELECT TO "authenticated" USING (("user_id" = "auth"."uid"()));



CREATE POLICY "Sovereign Owner Manage Appointments" ON "public"."appointments" TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "appointments"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"())))));



CREATE POLICY "Sovereign Owner Manage Commissions" ON "public"."commission_settings" TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "commission_settings"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"())))));



CREATE POLICY "Sovereign Owner Manage Customers" ON "public"."customers" TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "customers"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"())))));



CREATE POLICY "Sovereign Owner Manage Expenses" ON "public"."barbershop_expenses" TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "barbershop_expenses"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"())))));



CREATE POLICY "Sovereign Owner View Ledger" ON "public"."financial_ledger" FOR SELECT TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "financial_ledger"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"())))));



CREATE POLICY "Sovereign Staff Read Appointments" ON "public"."appointments" FOR SELECT TO "authenticated" USING (((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "appointments"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"())))) OR (EXISTS ( SELECT 1
   FROM "public"."barbers"
  WHERE (("barbers"."barbershop_id" = "appointments"."barbershop_id") AND ("barbers"."user_id" = "auth"."uid"()))))));



CREATE POLICY "Sovereign Staff View Customers" ON "public"."customers" FOR SELECT TO "authenticated" USING (((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "customers"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"())))) OR (EXISTS ( SELECT 1
   FROM "public"."barbers"
  WHERE (("barbers"."barbershop_id" = "customers"."barbershop_id") AND ("barbers"."user_id" = "auth"."uid"()))))));



CREATE POLICY "Staff view appointments" ON "public"."appointments_legacy" FOR SELECT USING ((("auth"."role"() = 'authenticated'::"text") AND ((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "appointments_legacy"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"())))) OR (EXISTS ( SELECT 1
   FROM "public"."barbers" "b"
  WHERE (("b"."barbershop_id" = "appointments_legacy"."barbershop_id") AND ("b"."user_id" = "auth"."uid"())))))));



CREATE POLICY "Staff view customers" ON "public"."customers" FOR SELECT USING ((("auth"."role"() = 'authenticated'::"text") AND ((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "customers"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"())))) OR (EXISTS ( SELECT 1
   FROM "public"."barbers" "b"
  WHERE (("b"."barbershop_id" = "customers"."barbershop_id") AND ("b"."user_id" = "auth"."uid"())))))));



CREATE POLICY "Staff view loyalty points" ON "public"."loyalty_points" FOR SELECT USING ((("auth"."role"() = 'authenticated'::"text") AND ((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "loyalty_points"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"())))) OR (EXISTS ( SELECT 1
   FROM "public"."barbers" "b"
  WHERE (("b"."barbershop_id" = "loyalty_points"."barbershop_id") AND ("b"."user_id" = "auth"."uid"())))))));



CREATE POLICY "SuperAdmin Only Retention Logs" ON "public"."data_retention_audit_log" TO "service_role" USING (true);



CREATE POLICY "System can insert security events" ON "public"."security_events" FOR INSERT WITH CHECK (true);



CREATE POLICY "System can manage commissions" ON "public"."commissions" USING (("auth"."role"() = 'service_role'::"text")) WITH CHECK (("auth"."role"() = 'service_role'::"text"));



CREATE POLICY "Tokens públicos podem ser lidos" ON "public"."appointment_tokens" FOR SELECT USING ((("expires_at" > "now"()) AND ("used_at" IS NULL)));



CREATE POLICY "User can view own profile" ON "public"."profiles" FOR SELECT TO "authenticated" USING (("auth"."uid"() = "id"));



CREATE POLICY "Users can cancel own appointments" ON "public"."appointments_legacy" FOR UPDATE TO "authenticated" USING (("customer_id" IN ( SELECT "customers"."id"
   FROM "public"."customers"
  WHERE ("customers"."user_id" = "auth"."uid"())))) WITH CHECK (("customer_id" IN ( SELECT "customers"."id"
   FROM "public"."customers"
  WHERE ("customers"."user_id" = "auth"."uid"()))));



CREATE POLICY "Users can insert own profile" ON "public"."profiles" FOR INSERT WITH CHECK (("auth"."uid"() = "id"));



CREATE POLICY "Users can insert their own security profile" ON "public"."user_security_profiles" FOR INSERT TO "authenticated" WITH CHECK (("auth"."uid"() = "user_id"));



CREATE POLICY "Users can link only unlinked customer records" ON "public"."customers" FOR UPDATE USING ((("user_id" IS NULL) OR ("user_id" = "auth"."uid"()))) WITH CHECK (("user_id" = "auth"."uid"()));



CREATE POLICY "Users can only insert own profile" ON "public"."profiles" FOR INSERT WITH CHECK (("id" = "auth"."uid"()));



CREATE POLICY "Users can select their own security profile" ON "public"."user_security_profiles" FOR SELECT TO "authenticated" USING (("auth"."uid"() = "user_id"));



CREATE POLICY "Users can update only their own profile" ON "public"."profiles" FOR UPDATE TO "authenticated" USING (("auth"."uid"() = "id")) WITH CHECK (("auth"."uid"() = "id"));



CREATE POLICY "Users can update own profile" ON "public"."profiles" FOR UPDATE USING (("auth"."uid"() = "id"));



CREATE POLICY "Users can update their own security profile" ON "public"."user_security_profiles" FOR UPDATE TO "authenticated" USING (("auth"."uid"() = "user_id")) WITH CHECK (("auth"."uid"() = "user_id"));



CREATE POLICY "Users can view customers of their barbershop" ON "public"."customers" FOR SELECT TO "authenticated" USING (("barbershop_id" IN ( SELECT "barbershops"."id"
   FROM "public"."barbershops"
  WHERE ("barbershops"."owner_id" = "auth"."uid"()))));



CREATE POLICY "Users can view only their own profile" ON "public"."profiles" FOR SELECT TO "authenticated" USING (("auth"."uid"() = "id"));



CREATE POLICY "Users can view own events" ON "public"."user_events" FOR SELECT USING (("auth"."uid"() = "user_id"));



CREATE POLICY "Users can view own profile" ON "public"."profiles" FOR SELECT TO "authenticated" USING (("auth"."uid"() = "id"));



CREATE POLICY "Users can view own subscription" ON "public"."subscriptions" FOR SELECT USING (("auth"."uid"() = "user_id"));



CREATE POLICY "Users can view own subscription override" ON "public"."subscription_overrides" FOR SELECT TO "authenticated" USING (("auth"."uid"() = "user_id"));



CREATE POLICY "Users can view their own audit logs" ON "public"."permission_audit_log" FOR SELECT USING (("user_id" = "auth"."uid"()));



ALTER TABLE "public"."_sovereign_audit_log" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."appointment_cancellations" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."appointment_tokens" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."appointments" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."appointments_default" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."appointments_legacy" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."appointments_p2024" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."appointments_p2025" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."appointments_p2026" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "appt_default_barbershop_owners" ON "public"."appointments_default" FOR SELECT TO "authenticated" USING ((("barbershop_id" IN ( SELECT "barbershops"."id"
   FROM "public"."barbershops"
  WHERE ("barbershops"."owner_id" = "auth"."uid"()))) OR ("barber_id" IN ( SELECT "barbers"."id"
   FROM "public"."barbers"
  WHERE ("barbers"."user_id" = "auth"."uid"())))));



CREATE POLICY "appt_p2024_barbershop_owners" ON "public"."appointments_p2024" FOR SELECT TO "authenticated" USING ((("barbershop_id" IN ( SELECT "barbershops"."id"
   FROM "public"."barbershops"
  WHERE ("barbershops"."owner_id" = "auth"."uid"()))) OR ("barber_id" IN ( SELECT "barbers"."id"
   FROM "public"."barbers"
  WHERE ("barbers"."user_id" = "auth"."uid"())))));



CREATE POLICY "appt_p2025_barbershop_owners" ON "public"."appointments_p2025" FOR SELECT TO "authenticated" USING ((("barbershop_id" IN ( SELECT "barbershops"."id"
   FROM "public"."barbershops"
  WHERE ("barbershops"."owner_id" = "auth"."uid"()))) OR ("barber_id" IN ( SELECT "barbers"."id"
   FROM "public"."barbers"
  WHERE ("barbers"."user_id" = "auth"."uid"())))));



CREATE POLICY "appt_p2026_barbershop_owners" ON "public"."appointments_p2026" FOR SELECT TO "authenticated" USING ((("barbershop_id" IN ( SELECT "barbershops"."id"
   FROM "public"."barbershops"
  WHERE ("barbershops"."owner_id" = "auth"."uid"()))) OR ("barber_id" IN ( SELECT "barbers"."id"
   FROM "public"."barbers"
  WHERE ("barbers"."user_id" = "auth"."uid"())))));



CREATE POLICY "audit_events_no_delete" ON "public"."sovereign_audit_events" FOR DELETE TO "authenticated", "anon" USING (false);



CREATE POLICY "audit_events_no_update" ON "public"."sovereign_audit_events" FOR UPDATE TO "authenticated", "anon" USING (false);



ALTER TABLE "public"."auth_otps" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."backup_codes" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."barbers" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."barbershop_expenses" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."barbershops" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."bi_log" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "bi_log_service_only" ON "public"."bi_log" TO "authenticated", "anon" USING (false);



ALTER TABLE "public"."cancel_reasons" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."commission_settings" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."commissions" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."cron_health_logs" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."csp_violations" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."customer_magic_links" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."customers" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."daily_metrics" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."data_retention_audit_log" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."data_retention_log" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."expenses" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."financial_ledger" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."login_attempts" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "login_attempts_no_select_anon" ON "public"."login_attempts" AS RESTRICTIVE FOR SELECT TO "anon" USING (false);



CREATE POLICY "login_attempts_no_select_authenticated" ON "public"."login_attempts" AS RESTRICTIVE FOR SELECT TO "authenticated" USING (false);



ALTER TABLE "public"."loyalty_points" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."mfa_recovery_attempts" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."notification_queue" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "notification_queue_anon_block" ON "public"."notification_queue" TO "anon" USING (false);



CREATE POLICY "notification_queue_service_only" ON "public"."notification_queue" TO "authenticated" USING (false);



CREATE POLICY "owners_manage_barbershop_roles" ON "public"."user_roles" TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "user_roles"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"()))))) WITH CHECK ((EXISTS ( SELECT 1
   FROM "public"."barbershops"
  WHERE (("barbershops"."id" = "user_roles"."barbershop_id") AND ("barbershops"."owner_id" = "auth"."uid"())))));



ALTER TABLE "public"."permission_audit_log" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."plans" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."products" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."profiles" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."rate_limits" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."salary_expenses" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."sale_items" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."sales" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."security_events" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."services" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."sovereign_audit_events" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."subscription_logs" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."subscription_overrides" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."subscriptions" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."system_settings" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."user_events" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."user_roles" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "user_roles_self_read_only" ON "public"."user_roles" FOR SELECT TO "authenticated" USING (("auth"."uid"() = "user_id"));



ALTER TABLE "public"."user_security_profiles" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."webhook_events" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "webhook_events_service_only_insert" ON "public"."webhook_events" FOR INSERT TO "authenticated", "anon" WITH CHECK (false);



CREATE POLICY "webhook_events_service_only_select" ON "public"."webhook_events" FOR SELECT TO "authenticated", "anon" USING (false);



CREATE POLICY "webhook_events_service_only_update" ON "public"."webhook_events" FOR UPDATE TO "authenticated", "anon" USING (false);



ALTER TABLE "public"."whatsapp_logs" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."whatsapp_retry_queue" ENABLE ROW LEVEL SECURITY;


GRANT USAGE ON SCHEMA "public" TO "postgres";
GRANT USAGE ON SCHEMA "public" TO "anon";
GRANT USAGE ON SCHEMA "public" TO "authenticated";
GRANT USAGE ON SCHEMA "public" TO "service_role";



GRANT ALL ON FUNCTION "public"."add_allowed_anon_action"("p_action" "text", "p_description" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."add_allowed_anon_action"("p_action" "text", "p_description" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."add_allowed_anon_action"("p_action" "text", "p_description" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."analyze_threat_events"() TO "anon";
GRANT ALL ON FUNCTION "public"."analyze_threat_events"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."analyze_threat_events"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."anonymize_inactive_customers"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."anonymize_inactive_customers"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."apply_data_retention_policy"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."apply_data_retention_policy"() TO "service_role";



GRANT ALL ON FUNCTION "public"."audit_barbers_commission_changes"() TO "anon";
GRANT ALL ON FUNCTION "public"."audit_barbers_commission_changes"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."audit_barbers_commission_changes"() TO "service_role";



GRANT ALL ON FUNCTION "public"."audit_barbershop_status_changes"() TO "anon";
GRANT ALL ON FUNCTION "public"."audit_barbershop_status_changes"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."audit_barbershop_status_changes"() TO "service_role";



GRANT ALL ON FUNCTION "public"."audit_commissions_trigger"() TO "anon";
GRANT ALL ON FUNCTION "public"."audit_commissions_trigger"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."audit_commissions_trigger"() TO "service_role";



GRANT ALL ON FUNCTION "public"."audit_services_financial_changes"() TO "anon";
GRANT ALL ON FUNCTION "public"."audit_services_financial_changes"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."audit_services_financial_changes"() TO "service_role";



GRANT ALL ON FUNCTION "public"."audit_user_roles_changes"() TO "anon";
GRANT ALL ON FUNCTION "public"."audit_user_roles_changes"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."audit_user_roles_changes"() TO "service_role";



GRANT ALL ON FUNCTION "public"."auto_track_appointment_events"() TO "anon";
GRANT ALL ON FUNCTION "public"."auto_track_appointment_events"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."auto_track_appointment_events"() TO "service_role";



GRANT ALL ON FUNCTION "public"."auto_track_barber_added"() TO "anon";
GRANT ALL ON FUNCTION "public"."auto_track_barber_added"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."auto_track_barber_added"() TO "service_role";



GRANT ALL ON FUNCTION "public"."auto_track_service_added"() TO "anon";
GRANT ALL ON FUNCTION "public"."auto_track_service_added"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."auto_track_service_added"() TO "service_role";



GRANT ALL ON FUNCTION "public"."buffer_bi_event"() TO "anon";
GRANT ALL ON FUNCTION "public"."buffer_bi_event"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."buffer_bi_event"() TO "service_role";



GRANT ALL ON FUNCTION "public"."calculate_appointment_end_time"() TO "anon";
GRANT ALL ON FUNCTION "public"."calculate_appointment_end_time"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."calculate_appointment_end_time"() TO "service_role";



GRANT ALL ON FUNCTION "public"."calculate_commission_for_appointment"("appt_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."calculate_commission_for_appointment"("appt_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."calculate_commission_for_appointment"("appt_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."cancel_appointment"("p_appointment_id" "uuid", "p_reason" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."cancel_appointment"("p_appointment_id" "uuid", "p_reason" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."cancel_appointment_atomically"("p_appointment_id" "uuid", "p_token" "text", "p_reason" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."cancel_appointment_atomically"("p_appointment_id" "uuid", "p_token" "text", "p_reason" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."cancel_appointment_atomically"("p_appointment_id" "uuid", "p_token" "text", "p_reason" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."check_account_lockout"("p_email" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."check_account_lockout"("p_email" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."check_account_lockout"("p_email" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."check_aha_moment"("p_user_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."check_aha_moment"("p_user_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."check_aha_moment"("p_user_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."check_and_expire_trials"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."check_and_expire_trials"() TO "service_role";



GRANT ALL ON FUNCTION "public"."check_appointment_conflict"("p_barber_id" "uuid", "p_appointment_date" "date", "p_appointment_time" time without time zone, "p_duration_minutes" integer, "p_padding_minutes" integer, "p_exclude_appointment_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."check_appointment_conflict"("p_barber_id" "uuid", "p_appointment_date" "date", "p_appointment_time" time without time zone, "p_duration_minutes" integer, "p_padding_minutes" integer, "p_exclude_appointment_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."check_appointment_conflict"("p_barber_id" "uuid", "p_appointment_date" "date", "p_appointment_time" time without time zone, "p_duration_minutes" integer, "p_padding_minutes" integer, "p_exclude_appointment_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."check_appointment_rate_limit"() TO "anon";
GRANT ALL ON FUNCTION "public"."check_appointment_rate_limit"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."check_appointment_rate_limit"() TO "service_role";



GRANT ALL ON FUNCTION "public"."check_barber_limit"() TO "anon";
GRANT ALL ON FUNCTION "public"."check_barber_limit"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."check_barber_limit"() TO "service_role";



GRANT ALL ON FUNCTION "public"."check_barber_limits"() TO "anon";
GRANT ALL ON FUNCTION "public"."check_barber_limits"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."check_barber_limits"() TO "service_role";



GRANT ALL ON FUNCTION "public"."check_default_partition_health"() TO "anon";
GRANT ALL ON FUNCTION "public"."check_default_partition_health"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."check_default_partition_health"() TO "service_role";



GRANT ALL ON FUNCTION "public"."check_mfa_compliance"() TO "anon";
GRANT ALL ON FUNCTION "public"."check_mfa_compliance"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."check_mfa_compliance"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."check_mfa_recovery_rate_limit"("p_user_id" "uuid", "p_ip" "inet") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."check_mfa_recovery_rate_limit"("p_user_id" "uuid", "p_ip" "inet") TO "service_role";



REVOKE ALL ON FUNCTION "public"."check_rate_limit"("p_key" "text", "p_limit" integer, "p_window_seconds" integer, "p_function_name" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."check_rate_limit"("p_key" "text", "p_limit" integer, "p_window_seconds" integer, "p_function_name" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."check_subscription_before_delete"() TO "anon";
GRANT ALL ON FUNCTION "public"."check_subscription_before_delete"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."check_subscription_before_delete"() TO "service_role";



GRANT ALL ON FUNCTION "public"."clean_html"("p_text" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."clean_html"("p_text" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."clean_html"("p_text" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."clean_metadata_input"() TO "anon";
GRANT ALL ON FUNCTION "public"."clean_metadata_input"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."clean_metadata_input"() TO "service_role";



GRANT ALL ON FUNCTION "public"."clean_storage_orphans"() TO "anon";
GRANT ALL ON FUNCTION "public"."clean_storage_orphans"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."clean_storage_orphans"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."cleanup_audit_logs"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."cleanup_audit_logs"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."cleanup_mfa_recovery_attempts"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."cleanup_mfa_recovery_attempts"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."cleanup_old_audit_logs"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."cleanup_old_audit_logs"() TO "service_role";



GRANT ALL ON FUNCTION "public"."cleanup_old_csp_violations"() TO "anon";
GRANT ALL ON FUNCTION "public"."cleanup_old_csp_violations"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."cleanup_old_csp_violations"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."cleanup_old_logs"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."cleanup_old_logs"() TO "service_role";



GRANT ALL ON FUNCTION "public"."cleanup_old_rate_limits"() TO "anon";
GRANT ALL ON FUNCTION "public"."cleanup_old_rate_limits"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."cleanup_old_rate_limits"() TO "service_role";



GRANT ALL ON FUNCTION "public"."cleanup_referential_integrity"() TO "anon";
GRANT ALL ON FUNCTION "public"."cleanup_referential_integrity"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."cleanup_referential_integrity"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."consolidate_bi_logs"("p_batch_size" integer) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."consolidate_bi_logs"("p_batch_size" integer) TO "service_role";



GRANT ALL ON FUNCTION "public"."create_appointment_v3"("p_customer_phone" "text", "p_customer_name" "text", "p_customer_email" "text", "p_date" "date", "p_time" time without time zone, "p_barber_id" "uuid", "p_service_id" "uuid", "p_barbershop_id" "uuid", "p_notes" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."create_appointment_v3"("p_customer_phone" "text", "p_customer_name" "text", "p_customer_email" "text", "p_date" "date", "p_time" time without time zone, "p_barber_id" "uuid", "p_service_id" "uuid", "p_barbershop_id" "uuid", "p_notes" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."create_appointment_v3"("p_customer_phone" "text", "p_customer_name" "text", "p_customer_email" "text", "p_date" "date", "p_time" time without time zone, "p_barber_id" "uuid", "p_service_id" "uuid", "p_barbershop_id" "uuid", "p_notes" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."create_barbershop_with_setup"("p_owner_id" "uuid", "p_name" "text", "p_slug" "text", "p_phone" "text", "p_address" "text", "p_description" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."create_barbershop_with_setup"("p_owner_id" "uuid", "p_name" "text", "p_slug" "text", "p_phone" "text", "p_address" "text", "p_description" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."create_barbershop_with_setup"("p_owner_id" "uuid", "p_name" "text", "p_slug" "text", "p_phone" "text", "p_address" "text", "p_description" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."create_public_appointment"("p_barbershop_slug" "text", "p_customer_name" "text", "p_customer_phone" "text", "p_customer_email" "text", "p_barber_id" "uuid", "p_service_id" "uuid", "p_appointment_date" "date", "p_appointment_time" time without time zone, "p_notes" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."create_public_appointment"("p_barbershop_slug" "text", "p_customer_name" "text", "p_customer_phone" "text", "p_customer_email" "text", "p_barber_id" "uuid", "p_service_id" "uuid", "p_appointment_date" "date", "p_appointment_time" time without time zone, "p_notes" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."create_public_appointment"("p_barbershop_slug" "text", "p_customer_name" "text", "p_customer_phone" "text", "p_customer_email" "text", "p_barber_id" "uuid", "p_service_id" "uuid", "p_appointment_date" "date", "p_appointment_time" time without time zone, "p_notes" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."create_public_appointment"("p_barbershop_slug" "text", "p_customer_name" "text", "p_customer_phone" "text", "p_customer_email" "text", "p_barber_id" "uuid", "p_service_id" "uuid", "p_appointment_date" "date", "p_appointment_time" time without time zone, "p_notes" "text", "p_barbershop_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."create_public_appointment"("p_barbershop_slug" "text", "p_customer_name" "text", "p_customer_phone" "text", "p_customer_email" "text", "p_barber_id" "uuid", "p_service_id" "uuid", "p_appointment_date" "date", "p_appointment_time" time without time zone, "p_notes" "text", "p_barbershop_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."delete_old_appointments"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."delete_old_appointments"() TO "service_role";



GRANT ALL ON FUNCTION "public"."ensure_whatsapp_confirmation"() TO "anon";
GRANT ALL ON FUNCTION "public"."ensure_whatsapp_confirmation"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."ensure_whatsapp_confirmation"() TO "service_role";



GRANT ALL ON FUNCTION "public"."execute_lgpd_retention_anonymization"() TO "anon";
GRANT ALL ON FUNCTION "public"."execute_lgpd_retention_anonymization"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."execute_lgpd_retention_anonymization"() TO "service_role";



GRANT ALL ON FUNCTION "public"."freeze_completed_financials"() TO "anon";
GRANT ALL ON FUNCTION "public"."freeze_completed_financials"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."freeze_completed_financials"() TO "service_role";



GRANT ALL ON FUNCTION "public"."generate_appointment_token"("p_appointment_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."generate_appointment_token"("p_appointment_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."generate_appointment_token"("p_appointment_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."generate_backup_codes_secure"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."generate_backup_codes_secure"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."generate_backup_codes_secure"() TO "service_role";



GRANT ALL ON FUNCTION "public"."get_appointment_by_token"("token_input" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."get_appointment_by_token"("token_input" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_appointment_by_token"("token_input" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_appointment_details_for_whatsapp"("p_appointment_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_appointments_for_1h_reminder"() TO "service_role";



GRANT ALL ON FUNCTION "public"."get_appointments_for_24h_reminder"() TO "service_role";



GRANT ALL ON FUNCTION "public"."get_available_slots"("p_barber_id" "uuid", "p_date" "date", "p_duration_minutes" integer, "p_start_time" time without time zone, "p_end_time" time without time zone, "p_interval_minutes" integer) TO "anon";
GRANT ALL ON FUNCTION "public"."get_available_slots"("p_barber_id" "uuid", "p_date" "date", "p_duration_minutes" integer, "p_start_time" time without time zone, "p_end_time" time without time zone, "p_interval_minutes" integer) TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_available_slots"("p_barber_id" "uuid", "p_date" "date", "p_duration_minutes" integer, "p_start_time" time without time zone, "p_end_time" time without time zone, "p_interval_minutes" integer) TO "service_role";



GRANT ALL ON FUNCTION "public"."get_available_times"("p_barbershop_slug" "text", "p_barber_id" "uuid", "p_date" "date") TO "anon";
GRANT ALL ON FUNCTION "public"."get_available_times"("p_barbershop_slug" "text", "p_barber_id" "uuid", "p_date" "date") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_available_times"("p_barbershop_slug" "text", "p_barber_id" "uuid", "p_date" "date") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_barber_monthly_report"("p_barbershop_id" "uuid", "p_barber_id" "uuid", "p_start_date" "date", "p_end_date" "date") TO "anon";
GRANT ALL ON FUNCTION "public"."get_barber_monthly_report"("p_barbershop_id" "uuid", "p_barber_id" "uuid", "p_start_date" "date", "p_end_date" "date") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_barber_monthly_report"("p_barbershop_id" "uuid", "p_barber_id" "uuid", "p_start_date" "date", "p_end_date" "date") TO "service_role";



REVOKE ALL ON FUNCTION "public"."get_barber_performance_metrics"("p_barbershop_id" "uuid", "p_start_date" timestamp with time zone, "p_end_date" timestamp with time zone) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."get_barber_performance_metrics"("p_barbershop_id" "uuid", "p_start_date" timestamp with time zone, "p_end_date" timestamp with time zone) TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_barber_performance_metrics"("p_barbershop_id" "uuid", "p_start_date" timestamp with time zone, "p_end_date" timestamp with time zone) TO "service_role";



GRANT ALL ON FUNCTION "public"."get_barbershop_settings"("barbershop_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."get_barbershop_settings"("barbershop_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_barbershop_settings"("barbershop_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."get_daily_metrics"("p_barbershop_id" "uuid", "p_start_date" timestamp with time zone, "p_end_date" timestamp with time zone) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."get_daily_metrics"("p_barbershop_id" "uuid", "p_start_date" timestamp with time zone, "p_end_date" timestamp with time zone) TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_daily_metrics"("p_barbershop_id" "uuid", "p_start_date" timestamp with time zone, "p_end_date" timestamp with time zone) TO "service_role";



GRANT ALL ON FUNCTION "public"."get_dashboard_kpis"("p_barbershop_id" "uuid", "p_start_date" timestamp with time zone, "p_end_date" timestamp with time zone) TO "anon";
GRANT ALL ON FUNCTION "public"."get_dashboard_kpis"("p_barbershop_id" "uuid", "p_start_date" timestamp with time zone, "p_end_date" timestamp with time zone) TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_dashboard_kpis"("p_barbershop_id" "uuid", "p_start_date" timestamp with time zone, "p_end_date" timestamp with time zone) TO "service_role";



REVOKE ALL ON FUNCTION "public"."get_dashboard_stats"("p_barbershop_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."get_dashboard_stats"("p_barbershop_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_dashboard_stats"("p_barbershop_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_dashboard_stats_v2"("p_barbershop_id" "uuid", "p_month" "date") TO "anon";
GRANT ALL ON FUNCTION "public"."get_dashboard_stats_v2"("p_barbershop_id" "uuid", "p_month" "date") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_dashboard_stats_v2"("p_barbershop_id" "uuid", "p_month" "date") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_day_availability"("p_barber_id" "uuid", "p_date" "date", "p_service_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."get_day_availability"("p_barber_id" "uuid", "p_date" "date", "p_service_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_day_availability"("p_barber_id" "uuid", "p_date" "date", "p_service_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_day_availability"("p_barbershop_id" "uuid", "p_barber_id" "uuid", "p_date" "date") TO "anon";
GRANT ALL ON FUNCTION "public"."get_day_availability"("p_barbershop_id" "uuid", "p_barber_id" "uuid", "p_date" "date") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_day_availability"("p_barbershop_id" "uuid", "p_barber_id" "uuid", "p_date" "date") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_financial_metrics"("p_barbershop_id" "uuid", "p_start_date" timestamp with time zone, "p_end_date" timestamp with time zone) TO "anon";
GRANT ALL ON FUNCTION "public"."get_financial_metrics"("p_barbershop_id" "uuid", "p_start_date" timestamp with time zone, "p_end_date" timestamp with time zone) TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_financial_metrics"("p_barbershop_id" "uuid", "p_start_date" timestamp with time zone, "p_end_date" timestamp with time zone) TO "service_role";



GRANT ALL ON FUNCTION "public"."get_monthly_financial_report"("p_barbershop_id" "uuid", "p_start_date" "date", "p_end_date" "date") TO "anon";
GRANT ALL ON FUNCTION "public"."get_monthly_financial_report"("p_barbershop_id" "uuid", "p_start_date" "date", "p_end_date" "date") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_monthly_financial_report"("p_barbershop_id" "uuid", "p_start_date" "date", "p_end_date" "date") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_plan_barber_limit"("plan_name" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."get_plan_barber_limit"("plan_name" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_plan_barber_limit"("plan_name" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_public_booking_data"("p_slug" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."get_public_booking_data"("p_slug" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_public_booking_data"("p_slug" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_server_time_iso"() TO "anon";
GRANT ALL ON FUNCTION "public"."get_server_time_iso"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_server_time_iso"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."get_top_services_metrics"("p_barbershop_id" "uuid", "p_start_date" timestamp with time zone, "p_end_date" timestamp with time zone) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."get_top_services_metrics"("p_barbershop_id" "uuid", "p_start_date" timestamp with time zone, "p_end_date" timestamp with time zone) TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_top_services_metrics"("p_barbershop_id" "uuid", "p_start_date" timestamp with time zone, "p_end_date" timestamp with time zone) TO "service_role";



REVOKE ALL ON FUNCTION "public"."get_user_id_by_phone"("p_phone" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."get_user_id_by_phone"("p_phone" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."get_user_identities"("p_user_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."get_user_identities"("p_user_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."get_user_identity"("p_user_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."get_user_identity"("p_user_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_user_setup_progress"("p_user_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."get_user_setup_progress"("p_user_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_user_setup_progress"("p_user_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_whatsapp_stats"("p_barbershop_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."get_whatsapp_stats"("p_barbershop_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_whatsapp_stats"("p_barbershop_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."get_whatsapp_status"("slug_input" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."get_whatsapp_status"("slug_input" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_whatsapp_status"("slug_input" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."guard_audit_logs_immutability"() TO "anon";
GRANT ALL ON FUNCTION "public"."guard_audit_logs_immutability"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."guard_audit_logs_immutability"() TO "service_role";



GRANT ALL ON FUNCTION "public"."guard_barbershop_changes"() TO "anon";
GRANT ALL ON FUNCTION "public"."guard_barbershop_changes"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."guard_barbershop_changes"() TO "service_role";



GRANT ALL ON FUNCTION "public"."handle_appointment_completion"() TO "anon";
GRANT ALL ON FUNCTION "public"."handle_appointment_completion"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."handle_appointment_completion"() TO "service_role";



GRANT ALL ON FUNCTION "public"."handle_appointment_financial_snapshot"() TO "anon";
GRANT ALL ON FUNCTION "public"."handle_appointment_financial_snapshot"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."handle_appointment_financial_snapshot"() TO "service_role";



GRANT ALL ON FUNCTION "public"."handle_new_user"() TO "anon";
GRANT ALL ON FUNCTION "public"."handle_new_user"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."handle_new_user"() TO "service_role";



GRANT ALL ON FUNCTION "public"."handle_updated_at"() TO "anon";
GRANT ALL ON FUNCTION "public"."handle_updated_at"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."handle_updated_at"() TO "service_role";



GRANT ALL ON FUNCTION "public"."has_barbershop_role"("_user_id" "uuid", "_barbershop_id" "uuid", "_role" "public"."app_role") TO "anon";
GRANT ALL ON FUNCTION "public"."has_barbershop_role"("_user_id" "uuid", "_barbershop_id" "uuid", "_role" "public"."app_role") TO "authenticated";
GRANT ALL ON FUNCTION "public"."has_barbershop_role"("_user_id" "uuid", "_barbershop_id" "uuid", "_role" "public"."app_role") TO "service_role";



GRANT ALL ON FUNCTION "public"."has_role"("_user_id" "uuid", "_role" "public"."app_role") TO "anon";
GRANT ALL ON FUNCTION "public"."has_role"("_user_id" "uuid", "_role" "public"."app_role") TO "authenticated";
GRANT ALL ON FUNCTION "public"."has_role"("_user_id" "uuid", "_role" "public"."app_role") TO "service_role";



GRANT ALL ON FUNCTION "public"."health_check"() TO "anon";
GRANT ALL ON FUNCTION "public"."health_check"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."health_check"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."is_account_locked_internal"("p_email" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."is_account_locked_internal"("p_email" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."is_system_locked"("p_key" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."is_system_locked"("p_key" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."is_system_locked"("p_key" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."is_valid_email"("p_email" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."is_valid_email"("p_email" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."is_valid_email"("p_email" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."log_audit_event"("p_table_name" "text", "p_record_id" "uuid", "p_action" "text", "p_category" "text", "p_old_data" "jsonb", "p_new_data" "jsonb") TO "anon";
GRANT ALL ON FUNCTION "public"."log_audit_event"("p_table_name" "text", "p_record_id" "uuid", "p_action" "text", "p_category" "text", "p_old_data" "jsonb", "p_new_data" "jsonb") TO "authenticated";
GRANT ALL ON FUNCTION "public"."log_audit_event"("p_table_name" "text", "p_record_id" "uuid", "p_action" "text", "p_category" "text", "p_old_data" "jsonb", "p_new_data" "jsonb") TO "service_role";



GRANT ALL ON FUNCTION "public"."log_mfa_event"() TO "anon";
GRANT ALL ON FUNCTION "public"."log_mfa_event"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."log_mfa_event"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."log_security_event"("p_type" "text", "p_severity" "text", "p_user_id" "uuid", "p_ip_address" "text", "p_details" "jsonb") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."log_security_event"("p_type" "text", "p_severity" "text", "p_user_id" "uuid", "p_ip_address" "text", "p_details" "jsonb") TO "service_role";



REVOKE ALL ON FUNCTION "public"."log_sovereign_batch_v2"("p_events" "jsonb"[]) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."log_sovereign_batch_v2"("p_events" "jsonb"[]) TO "service_role";



REVOKE ALL ON FUNCTION "public"."log_sovereign_event"("p_action" "text", "p_level" "text", "p_description" "text", "p_metadata" "jsonb", "p_user_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."log_sovereign_event"("p_action" "text", "p_level" "text", "p_description" "text", "p_metadata" "jsonb", "p_user_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."log_sovereign_event_v2"("p_action" "text", "p_level" "public"."audit_level", "p_description" "text", "p_metadata" "jsonb", "p_user_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."log_sovereign_event_v2"("p_action" "text", "p_level" "public"."audit_level", "p_description" "text", "p_metadata" "jsonb", "p_user_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."mark_event_as_alerted"("p_event_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."mark_event_as_alerted"("p_event_id" "uuid") TO "service_role";



GRANT ALL ON TABLE "public"."webhook_events" TO "anon";
GRANT ALL ON TABLE "public"."webhook_events" TO "authenticated";
GRANT ALL ON TABLE "public"."webhook_events" TO "service_role";



GRANT ALL ON FUNCTION "public"."pick_next_webhook_event"("p_worker_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."pick_next_webhook_event"("p_worker_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."pick_next_webhook_event"("p_worker_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."prevent_barber_hard_delete"() TO "anon";
GRANT ALL ON FUNCTION "public"."prevent_barber_hard_delete"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."prevent_barber_hard_delete"() TO "service_role";



GRANT ALL ON FUNCTION "public"."prevent_log_manipulation"() TO "anon";
GRANT ALL ON FUNCTION "public"."prevent_log_manipulation"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."prevent_log_manipulation"() TO "service_role";



GRANT ALL ON FUNCTION "public"."prevent_log_manipulation_backup"() TO "anon";
GRANT ALL ON FUNCTION "public"."prevent_log_manipulation_backup"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."prevent_log_manipulation_backup"() TO "service_role";



GRANT ALL ON FUNCTION "public"."prevent_role_escalation"() TO "anon";
GRANT ALL ON FUNCTION "public"."prevent_role_escalation"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."prevent_role_escalation"() TO "service_role";



GRANT ALL ON FUNCTION "public"."prevent_sensitive_updates"() TO "anon";
GRANT ALL ON FUNCTION "public"."prevent_sensitive_updates"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."prevent_sensitive_updates"() TO "service_role";



GRANT ALL ON FUNCTION "public"."prevent_service_hard_delete"() TO "anon";
GRANT ALL ON FUNCTION "public"."prevent_service_hard_delete"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."prevent_service_hard_delete"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."process_checkout_atomic"("p_appointment_id" "uuid", "p_cart_items" "jsonb", "p_payment_method" "text", "p_service_price" numeric, "p_products_total" numeric, "p_total_amount" numeric, "p_discount" numeric, "p_final_amount" numeric) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."process_checkout_atomic"("p_appointment_id" "uuid", "p_cart_items" "jsonb", "p_payment_method" "text", "p_service_price" numeric, "p_products_total" numeric, "p_total_amount" numeric, "p_discount" numeric, "p_final_amount" numeric) TO "service_role";



REVOKE ALL ON FUNCTION "public"."process_checkout_atomic"("p_appointment_id" "uuid", "p_cart_items" "public"."checkout_item"[], "p_payment_method" "text", "p_service_price" numeric, "p_products_total" numeric, "p_total_amount" numeric, "p_discount" numeric, "p_final_amount" numeric) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."process_checkout_atomic"("p_appointment_id" "uuid", "p_cart_items" "public"."checkout_item"[], "p_payment_method" "text", "p_service_price" numeric, "p_products_total" numeric, "p_total_amount" numeric, "p_discount" numeric, "p_final_amount" numeric) TO "service_role";



GRANT ALL ON FUNCTION "public"."protect_immutability_trigger"() TO "anon";
GRANT ALL ON FUNCTION "public"."protect_immutability_trigger"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."protect_immutability_trigger"() TO "service_role";



GRANT ALL ON FUNCTION "public"."queue_whatsapp_notification"("p_appointment_id" "uuid", "p_phone_number" "text", "p_message_type" "text", "p_template_data" "jsonb") TO "anon";
GRANT ALL ON FUNCTION "public"."queue_whatsapp_notification"("p_appointment_id" "uuid", "p_phone_number" "text", "p_message_type" "text", "p_template_data" "jsonb") TO "authenticated";
GRANT ALL ON FUNCTION "public"."queue_whatsapp_notification"("p_appointment_id" "uuid", "p_phone_number" "text", "p_message_type" "text", "p_template_data" "jsonb") TO "service_role";



REVOKE ALL ON FUNCTION "public"."reconcile_bi_metrics"("p_date" "date") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."reconcile_bi_metrics"("p_date" "date") TO "anon";
GRANT ALL ON FUNCTION "public"."reconcile_bi_metrics"("p_date" "date") TO "authenticated";
GRANT ALL ON FUNCTION "public"."reconcile_bi_metrics"("p_date" "date") TO "service_role";



GRANT ALL ON FUNCTION "public"."reconcile_bi_metrics"("p_barbershop_id" "uuid", "p_date" "date") TO "anon";
GRANT ALL ON FUNCTION "public"."reconcile_bi_metrics"("p_barbershop_id" "uuid", "p_date" "date") TO "authenticated";
GRANT ALL ON FUNCTION "public"."reconcile_bi_metrics"("p_barbershop_id" "uuid", "p_date" "date") TO "service_role";



GRANT ALL ON FUNCTION "public"."reconcile_bi_month"("p_barbershop_id" "uuid", "p_month" "date") TO "anon";
GRANT ALL ON FUNCTION "public"."reconcile_bi_month"("p_barbershop_id" "uuid", "p_month" "date") TO "authenticated";
GRANT ALL ON FUNCTION "public"."reconcile_bi_month"("p_barbershop_id" "uuid", "p_month" "date") TO "service_role";



GRANT ALL ON FUNCTION "public"."record_login_attempt"("p_email" "text", "p_success" boolean, "p_ip" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."record_login_attempt"("p_email" "text", "p_success" boolean, "p_ip" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."record_login_attempt"("p_email" "text", "p_success" boolean, "p_ip" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."reschedule_appointment"("p_old_appointment_id" "uuid", "p_new_date" "date", "p_new_time" time without time zone, "p_new_barber_id" "uuid", "p_new_service_id" "uuid", "p_token" "text", "p_auth_user_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."reschedule_appointment"("p_old_appointment_id" "uuid", "p_new_date" "date", "p_new_time" time without time zone, "p_new_barber_id" "uuid", "p_new_service_id" "uuid", "p_token" "text", "p_auth_user_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."reschedule_appointment"("p_old_appointment_id" "uuid", "p_new_date" "date", "p_new_time" time without time zone, "p_new_barber_id" "uuid", "p_new_service_id" "uuid", "p_token" "text", "p_auth_user_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."rescue_stuck_jobs"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."rescue_stuck_jobs"() TO "service_role";



GRANT ALL ON FUNCTION "public"."sanitize_xss_trigger"() TO "anon";
GRANT ALL ON FUNCTION "public"."sanitize_xss_trigger"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."sanitize_xss_trigger"() TO "service_role";



GRANT ALL ON FUNCTION "public"."set_appointment_duration"() TO "anon";
GRANT ALL ON FUNCTION "public"."set_appointment_duration"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."set_appointment_duration"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."set_mfa_verified_session"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."set_mfa_verified_session"() TO "service_role";



GRANT ALL ON FUNCTION "public"."set_time_and_duration"() TO "anon";
GRANT ALL ON FUNCTION "public"."set_time_and_duration"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."set_time_and_duration"() TO "service_role";



GRANT ALL ON FUNCTION "public"."snapshot_appointment_details"() TO "anon";
GRANT ALL ON FUNCTION "public"."snapshot_appointment_details"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."snapshot_appointment_details"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."soft_delete_tenant"("p_barbershop_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."soft_delete_tenant"("p_barbershop_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."sovereign_cleanup_routine"() TO "anon";
GRANT ALL ON FUNCTION "public"."sovereign_cleanup_routine"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."sovereign_cleanup_routine"() TO "service_role";



GRANT ALL ON FUNCTION "public"."sync_financial_from_appointments"() TO "anon";
GRANT ALL ON FUNCTION "public"."sync_financial_from_appointments"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."sync_financial_from_appointments"() TO "service_role";



GRANT ALL ON FUNCTION "public"."sync_subscription_to_claims"() TO "anon";
GRANT ALL ON FUNCTION "public"."sync_subscription_to_claims"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."sync_subscription_to_claims"() TO "service_role";



GRANT ALL ON FUNCTION "public"."sync_user_roles_to_app_metadata"() TO "anon";
GRANT ALL ON FUNCTION "public"."sync_user_roles_to_app_metadata"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."sync_user_roles_to_app_metadata"() TO "service_role";



GRANT ALL ON FUNCTION "public"."track_user_event"("p_user_id" "uuid", "p_event_type" "text", "p_barbershop_id" "uuid", "p_metadata" "jsonb") TO "anon";
GRANT ALL ON FUNCTION "public"."track_user_event"("p_user_id" "uuid", "p_event_type" "text", "p_barbershop_id" "uuid", "p_metadata" "jsonb") TO "authenticated";
GRANT ALL ON FUNCTION "public"."track_user_event"("p_user_id" "uuid", "p_event_type" "text", "p_barbershop_id" "uuid", "p_metadata" "jsonb") TO "service_role";



GRANT ALL ON FUNCTION "public"."trigger_calculate_commission"() TO "anon";
GRANT ALL ON FUNCTION "public"."trigger_calculate_commission"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."trigger_calculate_commission"() TO "service_role";



GRANT ALL ON FUNCTION "public"."update_daily_metrics"() TO "anon";
GRANT ALL ON FUNCTION "public"."update_daily_metrics"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."update_daily_metrics"() TO "service_role";



GRANT ALL ON FUNCTION "public"."update_subscription_overrides_updated_at"() TO "anon";
GRANT ALL ON FUNCTION "public"."update_subscription_overrides_updated_at"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."update_subscription_overrides_updated_at"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."update_subscription_safe"("p_barbershop_id" "uuid", "p_status" "text", "p_plan" "text", "p_ends_at" timestamp with time zone, "p_stripe_subscription_id" "text", "p_stripe_customer_id" "text", "p_event_created_at" bigint) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."update_subscription_safe"("p_barbershop_id" "uuid", "p_status" "text", "p_plan" "text", "p_ends_at" timestamp with time zone, "p_stripe_subscription_id" "text", "p_stripe_customer_id" "text", "p_event_created_at" bigint) TO "service_role";



GRANT ALL ON FUNCTION "public"."update_updated_at_column"() TO "anon";
GRANT ALL ON FUNCTION "public"."update_updated_at_column"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."update_updated_at_column"() TO "service_role";



GRANT ALL ON FUNCTION "public"."update_whatsapp_retry_queue_updated_at"() TO "anon";
GRANT ALL ON FUNCTION "public"."update_whatsapp_retry_queue_updated_at"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."update_whatsapp_retry_queue_updated_at"() TO "service_role";



GRANT ALL ON FUNCTION "public"."validate_whatsapp_cooldown"() TO "anon";
GRANT ALL ON FUNCTION "public"."validate_whatsapp_cooldown"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."validate_whatsapp_cooldown"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."verify_backup_code_secure"("p_code" "text", "p_user_id" "uuid", "p_ip" "inet") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."verify_backup_code_secure"("p_code" "text", "p_user_id" "uuid", "p_ip" "inet") TO "service_role";



GRANT ALL ON FUNCTION "public"."warn_default_partition_insert"() TO "anon";
GRANT ALL ON FUNCTION "public"."warn_default_partition_insert"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."warn_default_partition_insert"() TO "service_role";



GRANT ALL ON TABLE "public"."appointments" TO "anon";
GRANT ALL ON TABLE "public"."appointments" TO "authenticated";
GRANT ALL ON TABLE "public"."appointments" TO "service_role";



GRANT ALL ON TABLE "public"."customers" TO "service_role";
GRANT ALL ON TABLE "public"."customers" TO "authenticated";



GRANT ALL ON TABLE "public"."_sovereign_audit_log" TO "anon";
GRANT ALL ON TABLE "public"."_sovereign_audit_log" TO "authenticated";
GRANT ALL ON TABLE "public"."_sovereign_audit_log" TO "service_role";



GRANT ALL ON SEQUENCE "public"."_sovereign_audit_log_id_seq" TO "anon";
GRANT ALL ON SEQUENCE "public"."_sovereign_audit_log_id_seq" TO "authenticated";
GRANT ALL ON SEQUENCE "public"."_sovereign_audit_log_id_seq" TO "service_role";



GRANT ALL ON TABLE "public"."allowed_anon_actions" TO "anon";
GRANT ALL ON TABLE "public"."allowed_anon_actions" TO "authenticated";
GRANT ALL ON TABLE "public"."allowed_anon_actions" TO "service_role";



GRANT ALL ON TABLE "public"."appointment_cancellations" TO "anon";
GRANT ALL ON TABLE "public"."appointment_cancellations" TO "authenticated";
GRANT ALL ON TABLE "public"."appointment_cancellations" TO "service_role";



GRANT ALL ON TABLE "public"."appointments_legacy" TO "anon";
GRANT ALL ON TABLE "public"."appointments_legacy" TO "authenticated";
GRANT ALL ON TABLE "public"."appointments_legacy" TO "service_role";



GRANT ALL ON TABLE "public"."appointment_notifications_status" TO "anon";
GRANT ALL ON TABLE "public"."appointment_notifications_status" TO "authenticated";
GRANT ALL ON TABLE "public"."appointment_notifications_status" TO "service_role";



GRANT ALL ON TABLE "public"."appointment_tokens" TO "anon";
GRANT ALL ON TABLE "public"."appointment_tokens" TO "authenticated";
GRANT ALL ON TABLE "public"."appointment_tokens" TO "service_role";



GRANT ALL ON TABLE "public"."appointments_default" TO "anon";
GRANT ALL ON TABLE "public"."appointments_default" TO "authenticated";
GRANT ALL ON TABLE "public"."appointments_default" TO "service_role";



GRANT ALL ON TABLE "public"."appointments_p2024" TO "anon";
GRANT ALL ON TABLE "public"."appointments_p2024" TO "authenticated";
GRANT ALL ON TABLE "public"."appointments_p2024" TO "service_role";



GRANT ALL ON TABLE "public"."appointments_p2025" TO "anon";
GRANT ALL ON TABLE "public"."appointments_p2025" TO "authenticated";
GRANT ALL ON TABLE "public"."appointments_p2025" TO "service_role";



GRANT ALL ON TABLE "public"."appointments_p2026" TO "anon";
GRANT ALL ON TABLE "public"."appointments_p2026" TO "authenticated";
GRANT ALL ON TABLE "public"."appointments_p2026" TO "service_role";



GRANT ALL ON TABLE "public"."audit_action_registry" TO "anon";
GRANT ALL ON TABLE "public"."audit_action_registry" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_action_registry" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_2026_01" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_2026_01" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_2026_01" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_2026_02" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_2026_02" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_2026_02" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_2026_03" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_2026_03" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_2026_03" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_2026_04" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_2026_04" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_2026_04" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_2026_05" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_2026_05" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_2026_05" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_2026_06" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_2026_06" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_2026_06" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_2026_07" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_2026_07" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_2026_07" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_2026_08" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_2026_08" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_2026_08" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_2026_09" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_2026_09" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_2026_09" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_2026_10" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_2026_10" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_2026_10" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_2026_11" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_2026_11" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_2026_11" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_2026_12" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_2026_12" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_2026_12" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_2027_01" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_2027_01" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_2027_01" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_2027_02" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_2027_02" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_2027_02" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_2027_03" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_2027_03" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_2027_03" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_2027_04" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_2027_04" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_2027_04" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_2027_05" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_2027_05" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_2027_05" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_2027_06" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_2027_06" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_2027_06" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_2027_07" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_2027_07" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_2027_07" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_2027_08" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_2027_08" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_2027_08" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_2027_09" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_2027_09" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_2027_09" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_2027_10" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_2027_10" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_2027_10" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_2027_11" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_2027_11" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_2027_11" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_2027_12" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_2027_12" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_2027_12" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_2028_01" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_2028_01" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_2028_01" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_2028_02" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_2028_02" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_2028_02" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_2028_03" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_2028_03" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_2028_03" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_2028_04" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_2028_04" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_2028_04" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_2028_05" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_2028_05" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_2028_05" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_2028_06" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_2028_06" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_2028_06" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_2028_07" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_2028_07" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_2028_07" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_2028_08" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_2028_08" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_2028_08" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_2028_09" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_2028_09" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_2028_09" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_2028_10" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_2028_10" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_2028_10" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_2028_11" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_2028_11" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_2028_11" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_2028_12" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_2028_12" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_2028_12" TO "service_role";



GRANT ALL ON TABLE "public"."audit_logs_default" TO "anon";
GRANT ALL ON TABLE "public"."audit_logs_default" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_logs_default" TO "service_role";



GRANT ALL ON TABLE "public"."auth_otps" TO "anon";
GRANT ALL ON TABLE "public"."auth_otps" TO "authenticated";
GRANT ALL ON TABLE "public"."auth_otps" TO "service_role";



GRANT ALL ON TABLE "public"."backup_codes" TO "service_role";



GRANT ALL ON TABLE "public"."barbers" TO "anon";
GRANT ALL ON TABLE "public"."barbers" TO "authenticated";
GRANT ALL ON TABLE "public"."barbers" TO "service_role";



GRANT ALL ON TABLE "public"."barbershop_expenses" TO "anon";
GRANT ALL ON TABLE "public"."barbershop_expenses" TO "authenticated";
GRANT ALL ON TABLE "public"."barbershop_expenses" TO "service_role";



GRANT INSERT,REFERENCES,DELETE,TRIGGER,TRUNCATE,MAINTAIN,UPDATE ON TABLE "public"."barbershops" TO "anon";
GRANT INSERT,REFERENCES,DELETE,TRIGGER,TRUNCATE,MAINTAIN,UPDATE ON TABLE "public"."barbershops" TO "authenticated";
GRANT ALL ON TABLE "public"."barbershops" TO "service_role";



GRANT SELECT("id") ON TABLE "public"."barbershops" TO "anon";
GRANT SELECT("id") ON TABLE "public"."barbershops" TO "authenticated";



GRANT SELECT("owner_id") ON TABLE "public"."barbershops" TO "anon";
GRANT SELECT("owner_id") ON TABLE "public"."barbershops" TO "authenticated";



GRANT SELECT("name") ON TABLE "public"."barbershops" TO "anon";
GRANT SELECT("name") ON TABLE "public"."barbershops" TO "authenticated";



GRANT SELECT("slug") ON TABLE "public"."barbershops" TO "anon";
GRANT SELECT("slug") ON TABLE "public"."barbershops" TO "authenticated";



GRANT SELECT("description") ON TABLE "public"."barbershops" TO "anon";
GRANT SELECT("description") ON TABLE "public"."barbershops" TO "authenticated";



GRANT SELECT("logo_url") ON TABLE "public"."barbershops" TO "anon";
GRANT SELECT("logo_url") ON TABLE "public"."barbershops" TO "authenticated";



GRANT SELECT("phone") ON TABLE "public"."barbershops" TO "anon";
GRANT SELECT("phone") ON TABLE "public"."barbershops" TO "authenticated";



GRANT SELECT("address") ON TABLE "public"."barbershops" TO "anon";
GRANT SELECT("address") ON TABLE "public"."barbershops" TO "authenticated";



GRANT SELECT("primary_color") ON TABLE "public"."barbershops" TO "anon";
GRANT SELECT("primary_color") ON TABLE "public"."barbershops" TO "authenticated";



GRANT SELECT("secondary_color") ON TABLE "public"."barbershops" TO "anon";
GRANT SELECT("secondary_color") ON TABLE "public"."barbershops" TO "authenticated";



GRANT SELECT("loyalty_enabled") ON TABLE "public"."barbershops" TO "anon";
GRANT SELECT("loyalty_enabled") ON TABLE "public"."barbershops" TO "authenticated";



GRANT SELECT("loyalty_points_per_service") ON TABLE "public"."barbershops" TO "anon";
GRANT SELECT("loyalty_points_per_service") ON TABLE "public"."barbershops" TO "authenticated";



GRANT SELECT("loyalty_points_for_reward") ON TABLE "public"."barbershops" TO "anon";
GRANT SELECT("loyalty_points_for_reward") ON TABLE "public"."barbershops" TO "authenticated";



GRANT SELECT("loyalty_reward_service") ON TABLE "public"."barbershops" TO "anon";
GRANT SELECT("loyalty_reward_service") ON TABLE "public"."barbershops" TO "authenticated";



GRANT SELECT("subscription_plan") ON TABLE "public"."barbershops" TO "anon";
GRANT SELECT("subscription_plan") ON TABLE "public"."barbershops" TO "authenticated";



GRANT SELECT("subscription_status") ON TABLE "public"."barbershops" TO "anon";
GRANT SELECT("subscription_status") ON TABLE "public"."barbershops" TO "authenticated";



GRANT SELECT("trial_ends_at") ON TABLE "public"."barbershops" TO "anon";
GRANT SELECT("trial_ends_at") ON TABLE "public"."barbershops" TO "authenticated";



GRANT SELECT("created_at") ON TABLE "public"."barbershops" TO "anon";
GRANT SELECT("created_at") ON TABLE "public"."barbershops" TO "authenticated";



GRANT ALL ON TABLE "public"."bi_log" TO "anon";
GRANT ALL ON TABLE "public"."bi_log" TO "authenticated";
GRANT ALL ON TABLE "public"."bi_log" TO "service_role";



GRANT ALL ON SEQUENCE "public"."bi_log_id_seq" TO "anon";
GRANT ALL ON SEQUENCE "public"."bi_log_id_seq" TO "authenticated";
GRANT ALL ON SEQUENCE "public"."bi_log_id_seq" TO "service_role";



GRANT ALL ON TABLE "public"."blacklisted_ips" TO "anon";
GRANT ALL ON TABLE "public"."blacklisted_ips" TO "authenticated";
GRANT ALL ON TABLE "public"."blacklisted_ips" TO "service_role";



GRANT ALL ON TABLE "public"."cancel_reasons" TO "anon";
GRANT ALL ON TABLE "public"."cancel_reasons" TO "authenticated";
GRANT ALL ON TABLE "public"."cancel_reasons" TO "service_role";



GRANT ALL ON TABLE "public"."commission_settings" TO "anon";
GRANT ALL ON TABLE "public"."commission_settings" TO "authenticated";
GRANT ALL ON TABLE "public"."commission_settings" TO "service_role";



GRANT ALL ON TABLE "public"."commissions" TO "anon";
GRANT ALL ON TABLE "public"."commissions" TO "authenticated";
GRANT ALL ON TABLE "public"."commissions" TO "service_role";



GRANT ALL ON TABLE "public"."cron_health_logs" TO "anon";
GRANT ALL ON TABLE "public"."cron_health_logs" TO "authenticated";
GRANT ALL ON TABLE "public"."cron_health_logs" TO "service_role";



GRANT SELECT,REFERENCES,DELETE,TRIGGER,TRUNCATE,MAINTAIN,UPDATE ON TABLE "public"."csp_violations" TO "anon";
GRANT SELECT,REFERENCES,DELETE,TRIGGER,TRUNCATE,MAINTAIN,UPDATE ON TABLE "public"."csp_violations" TO "authenticated";
GRANT ALL ON TABLE "public"."csp_violations" TO "service_role";



GRANT ALL ON TABLE "public"."customer_magic_links" TO "anon";
GRANT ALL ON TABLE "public"."customer_magic_links" TO "authenticated";
GRANT ALL ON TABLE "public"."customer_magic_links" TO "service_role";



GRANT ALL ON TABLE "public"."daily_metrics" TO "anon";
GRANT ALL ON TABLE "public"."daily_metrics" TO "authenticated";
GRANT ALL ON TABLE "public"."daily_metrics" TO "service_role";



GRANT ALL ON TABLE "public"."data_retention_audit_log" TO "anon";
GRANT ALL ON TABLE "public"."data_retention_audit_log" TO "authenticated";
GRANT ALL ON TABLE "public"."data_retention_audit_log" TO "service_role";



GRANT ALL ON TABLE "public"."data_retention_log" TO "service_role";



GRANT ALL ON TABLE "public"."expenses" TO "anon";
GRANT ALL ON TABLE "public"."expenses" TO "authenticated";
GRANT ALL ON TABLE "public"."expenses" TO "service_role";



GRANT ALL ON TABLE "public"."financial_ledger" TO "anon";
GRANT ALL ON TABLE "public"."financial_ledger" TO "authenticated";
GRANT ALL ON TABLE "public"."financial_ledger" TO "service_role";



GRANT ALL ON TABLE "public"."login_attempts" TO "service_role";



GRANT ALL ON TABLE "public"."loyalty_points" TO "anon";
GRANT ALL ON TABLE "public"."loyalty_points" TO "authenticated";
GRANT ALL ON TABLE "public"."loyalty_points" TO "service_role";



GRANT ALL ON TABLE "public"."mfa_recovery_attempts" TO "service_role";



GRANT ALL ON TABLE "public"."mfa_recovery_audit" TO "service_role";



GRANT ALL ON TABLE "public"."notification_queue" TO "service_role";



GRANT ALL ON TABLE "public"."security_events" TO "service_role";



GRANT ALL ON TABLE "public"."pending_security_alerts" TO "anon";
GRANT ALL ON TABLE "public"."pending_security_alerts" TO "authenticated";
GRANT ALL ON TABLE "public"."pending_security_alerts" TO "service_role";



GRANT ALL ON TABLE "public"."permission_audit_log" TO "anon";
GRANT ALL ON TABLE "public"."permission_audit_log" TO "authenticated";
GRANT ALL ON TABLE "public"."permission_audit_log" TO "service_role";



GRANT ALL ON TABLE "public"."plans" TO "anon";
GRANT ALL ON TABLE "public"."plans" TO "authenticated";
GRANT ALL ON TABLE "public"."plans" TO "service_role";



GRANT ALL ON TABLE "public"."products" TO "anon";
GRANT ALL ON TABLE "public"."products" TO "authenticated";
GRANT ALL ON TABLE "public"."products" TO "service_role";



GRANT ALL ON TABLE "public"."profiles" TO "anon";
GRANT ALL ON TABLE "public"."profiles" TO "authenticated";
GRANT ALL ON TABLE "public"."profiles" TO "service_role";



GRANT ALL ON TABLE "public"."public_barbers" TO "anon";
GRANT ALL ON TABLE "public"."public_barbers" TO "authenticated";
GRANT ALL ON TABLE "public"."public_barbers" TO "service_role";



GRANT ALL ON TABLE "public"."public_barbers_secure" TO "anon";
GRANT ALL ON TABLE "public"."public_barbers_secure" TO "authenticated";
GRANT ALL ON TABLE "public"."public_barbers_secure" TO "service_role";



GRANT ALL ON TABLE "public"."public_barbers_ultra_safe" TO "anon";
GRANT ALL ON TABLE "public"."public_barbers_ultra_safe" TO "authenticated";
GRANT ALL ON TABLE "public"."public_barbers_ultra_safe" TO "service_role";



GRANT ALL ON TABLE "public"."public_barbershops" TO "anon";
GRANT ALL ON TABLE "public"."public_barbershops" TO "authenticated";
GRANT ALL ON TABLE "public"."public_barbershops" TO "service_role";



GRANT ALL ON TABLE "public"."public_barbershops_complete" TO "anon";
GRANT ALL ON TABLE "public"."public_barbershops_complete" TO "authenticated";
GRANT ALL ON TABLE "public"."public_barbershops_complete" TO "service_role";



GRANT ALL ON TABLE "public"."public_barbershops_safe" TO "anon";
GRANT ALL ON TABLE "public"."public_barbershops_safe" TO "authenticated";
GRANT ALL ON TABLE "public"."public_barbershops_safe" TO "service_role";



GRANT ALL ON TABLE "public"."public_barbershops_ultra_safe" TO "anon";
GRANT ALL ON TABLE "public"."public_barbershops_ultra_safe" TO "authenticated";
GRANT ALL ON TABLE "public"."public_barbershops_ultra_safe" TO "service_role";



GRANT ALL ON TABLE "public"."services" TO "anon";
GRANT ALL ON TABLE "public"."services" TO "authenticated";
GRANT ALL ON TABLE "public"."services" TO "service_role";



GRANT ALL ON TABLE "public"."public_services" TO "anon";
GRANT ALL ON TABLE "public"."public_services" TO "authenticated";
GRANT ALL ON TABLE "public"."public_services" TO "service_role";



GRANT ALL ON TABLE "public"."public_services_safe" TO "anon";
GRANT ALL ON TABLE "public"."public_services_safe" TO "authenticated";
GRANT ALL ON TABLE "public"."public_services_safe" TO "service_role";



GRANT ALL ON TABLE "public"."rate_limits" TO "service_role";



GRANT ALL ON TABLE "public"."salary_expenses" TO "anon";
GRANT ALL ON TABLE "public"."salary_expenses" TO "authenticated";
GRANT ALL ON TABLE "public"."salary_expenses" TO "service_role";



GRANT ALL ON TABLE "public"."sale_items" TO "anon";
GRANT ALL ON TABLE "public"."sale_items" TO "authenticated";
GRANT ALL ON TABLE "public"."sale_items" TO "service_role";



GRANT ALL ON TABLE "public"."sales" TO "anon";
GRANT ALL ON TABLE "public"."sales" TO "authenticated";
GRANT ALL ON TABLE "public"."sales" TO "service_role";



GRANT SELECT,REFERENCES,TRIGGER,TRUNCATE,MAINTAIN ON TABLE "public"."sovereign_audit_events" TO "anon";
GRANT SELECT,REFERENCES,TRIGGER,TRUNCATE,MAINTAIN ON TABLE "public"."sovereign_audit_events" TO "authenticated";
GRANT ALL ON TABLE "public"."sovereign_audit_events" TO "service_role";



GRANT ALL ON TABLE "public"."subscription_logs" TO "anon";
GRANT ALL ON TABLE "public"."subscription_logs" TO "authenticated";
GRANT ALL ON TABLE "public"."subscription_logs" TO "service_role";



GRANT ALL ON TABLE "public"."subscription_overrides" TO "anon";
GRANT ALL ON TABLE "public"."subscription_overrides" TO "authenticated";
GRANT ALL ON TABLE "public"."subscription_overrides" TO "service_role";



GRANT ALL ON TABLE "public"."subscriptions" TO "anon";
GRANT ALL ON TABLE "public"."subscriptions" TO "authenticated";
GRANT ALL ON TABLE "public"."subscriptions" TO "service_role";



GRANT ALL ON TABLE "public"."suspicious_permission_changes" TO "anon";
GRANT ALL ON TABLE "public"."suspicious_permission_changes" TO "authenticated";
GRANT ALL ON TABLE "public"."suspicious_permission_changes" TO "service_role";



GRANT ALL ON TABLE "public"."system_health_monitor" TO "anon";
GRANT ALL ON TABLE "public"."system_health_monitor" TO "authenticated";
GRANT ALL ON TABLE "public"."system_health_monitor" TO "service_role";



GRANT ALL ON TABLE "public"."system_settings" TO "anon";
GRANT ALL ON TABLE "public"."system_settings" TO "authenticated";
GRANT ALL ON TABLE "public"."system_settings" TO "service_role";



GRANT ALL ON TABLE "public"."user_events" TO "anon";
GRANT ALL ON TABLE "public"."user_events" TO "authenticated";
GRANT ALL ON TABLE "public"."user_events" TO "service_role";



GRANT ALL ON TABLE "public"."user_roles" TO "anon";
GRANT ALL ON TABLE "public"."user_roles" TO "authenticated";
GRANT ALL ON TABLE "public"."user_roles" TO "service_role";



GRANT ALL ON TABLE "public"."user_security_profiles" TO "anon";
GRANT ALL ON TABLE "public"."user_security_profiles" TO "authenticated";
GRANT ALL ON TABLE "public"."user_security_profiles" TO "service_role";



GRANT ALL ON TABLE "public"."v_audit_logs_health" TO "anon";
GRANT ALL ON TABLE "public"."v_audit_logs_health" TO "authenticated";
GRANT ALL ON TABLE "public"."v_audit_logs_health" TO "service_role";



GRANT ALL ON TABLE "public"."v_sovereign_alerts" TO "anon";
GRANT ALL ON TABLE "public"."v_sovereign_alerts" TO "authenticated";
GRANT ALL ON TABLE "public"."v_sovereign_alerts" TO "service_role";



GRANT ALL ON TABLE "public"."view_daily_metrics_unified" TO "anon";
GRANT ALL ON TABLE "public"."view_daily_metrics_unified" TO "authenticated";
GRANT ALL ON TABLE "public"."view_daily_metrics_unified" TO "service_role";



GRANT ALL ON TABLE "public"."whatsapp_logs" TO "service_role";



GRANT ALL ON TABLE "public"."whatsapp_retry_queue" TO "service_role";



ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES TO "anon";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES TO "service_role";






ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "anon";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "service_role";






ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "anon";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "service_role";







