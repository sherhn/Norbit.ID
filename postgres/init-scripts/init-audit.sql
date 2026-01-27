-- Создаем таблицу для аудит-логов
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    table_name TEXT NOT NULL,
    operation CHAR(1) NOT NULL CHECK (operation IN ('I','U','D')),  -- Оставляем CHAR(1)
    old_data JSONB,
    new_data JSONB,
    changed_fields JSONB,
    changed_at TIMESTAMPTZ DEFAULT NOW(),
    db_user TEXT DEFAULT CURRENT_USER,
    application_name TEXT,
    client_ip INET,
    transaction_id BIGINT
);

-- Индексы для производительности
CREATE INDEX IF NOT EXISTS idx_audit_log_table_name ON audit_log(table_name);
CREATE INDEX IF NOT EXISTS idx_audit_log_operation ON audit_log(operation);
CREATE INDEX IF NOT EXISTS idx_audit_log_changed_at ON audit_log(changed_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_table_operation ON audit_log(table_name, operation);

-- Комментарии к таблице и полям
COMMENT ON TABLE audit_log IS 'Таблица для аудита изменений данных';
COMMENT ON COLUMN audit_log.table_name IS 'Имя изменённой таблицы';
COMMENT ON COLUMN audit_log.operation IS 'Тип операции: I=INSERT, U=UPDATE, D=DELETE';
COMMENT ON COLUMN audit_log.old_data IS 'Данные до изменения (для UPDATE/DELETE)';
COMMENT ON COLUMN audit_log.new_data IS 'Данные после изменения (для INSERT/UPDATE)';
COMMENT ON COLUMN audit_log.changed_fields IS 'Изменённые поля и их старые/новые значения';
COMMENT ON COLUMN audit_log.changed_at IS 'Временная метка изменения';
COMMENT ON COLUMN audit_log.db_user IS 'Пользователь БД, выполнивший операцию';
COMMENT ON COLUMN audit_log.application_name IS 'Имя приложения (из connection string)';
COMMENT ON COLUMN audit_log.client_ip IS 'IP-адрес клиента (если доступно)';
COMMENT ON COLUMN audit_log.transaction_id IS 'ID транзакции';


-- Универсальная функция для аудита
CREATE OR REPLACE FUNCTION audit_trigger_function()
RETURNS TRIGGER AS $$
DECLARE
    _old_data JSONB;
    _new_data JSONB;
    _changed_fields JSONB;
    _application_name TEXT;
    _client_ip INET;
    _operation_char CHAR(1);
BEGIN
    -- Получаем контекстные данные
    _application_name := current_setting('application_name', true);

    -- Пытаемся получить IP клиента (работает не во всех конфигурациях)
    BEGIN
        _client_ip := inet_client_addr();
    EXCEPTION WHEN OTHERS THEN
        _client_ip := NULL;
    END;

    -- Преобразуем операцию в один символ
    CASE TG_OP
        WHEN 'INSERT' THEN _operation_char := 'I';
        WHEN 'UPDATE' THEN _operation_char := 'U';
        WHEN 'DELETE' THEN _operation_char := 'D';
    END CASE;

    -- Обработка разных типов операций
    IF TG_OP = 'INSERT' THEN
        _new_data := to_jsonb(NEW);
        _old_data := NULL;
        _changed_fields := NULL;

    ELSIF TG_OP = 'UPDATE' THEN
        _old_data := to_jsonb(OLD);
        _new_data := to_jsonb(NEW);

        -- Определяем конкретные измененные поля
        SELECT jsonb_object_agg(
            key,
            jsonb_build_object('old_value', old_val, 'new_value', new_val)
        )
        INTO _changed_fields
        FROM (
            SELECT
                key,
                old_val,
                new_val
            FROM jsonb_each(to_jsonb(OLD)) AS old_data(key, old_val)
            JOIN jsonb_each(to_jsonb(NEW)) AS new_data(key, new_val)
            USING (key)
            WHERE old_val IS DISTINCT FROM new_val
        ) AS changed;

    ELSIF TG_OP = 'DELETE' THEN
        _old_data := to_jsonb(OLD);
        _new_data := NULL;
        _changed_fields := NULL;

    END IF;

    -- Вставляем запись в аудит-лог
    INSERT INTO audit_log (
        table_name,
        operation,
        old_data,
        new_data,
        changed_fields,
        db_user,
        application_name,
        client_ip,
        transaction_id
    ) VALUES (
        TG_TABLE_NAME,
        _operation_char,  -- Используем преобразованный символ
        _old_data,
        _new_data,
        _changed_fields,
        CURRENT_USER,
        _application_name,
        _client_ip,
        txid_current()
    );

    -- Для INSERT и UPDATE возвращаем NEW, для DELETE - OLD
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    ELSE
        RETURN NEW;
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Функция для включения аудита на таблице
CREATE OR REPLACE FUNCTION enable_table_audit(
    target_table TEXT,
    schema_name TEXT DEFAULT 'public'
) RETURNS VOID AS $$
DECLARE
    trigger_name TEXT;
BEGIN
    trigger_name := 'audit_trigger_' || target_table;

    EXECUTE format(
        'DROP TRIGGER IF EXISTS %I ON %I.%I;
         CREATE TRIGGER %I
         AFTER INSERT OR UPDATE OR DELETE ON %I.%I
         FOR EACH ROW EXECUTE FUNCTION audit_trigger_function();',
        trigger_name, schema_name, target_table,
        trigger_name, schema_name, target_table
    );

    RAISE NOTICE 'Аудит включен для таблицы %.%', schema_name, target_table;
END;
$$ LANGUAGE plpgsql;

-- Функция для отключения аудита на таблице
CREATE OR REPLACE FUNCTION disable_table_audit(
    target_table TEXT,
    schema_name TEXT DEFAULT 'public'
) RETURNS VOID AS $$
DECLARE
    trigger_name TEXT;
BEGIN
    trigger_name := 'audit_trigger_' || target_table;

    EXECUTE format(
        'DROP TRIGGER IF EXISTS %I ON %I.%I;',
        trigger_name, schema_name, target_table
    );

    RAISE NOTICE 'Аудит отключен для таблицы %.%', schema_name, target_table;
END;
$$ LANGUAGE plpgsql;