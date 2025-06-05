#!/bin/bash

# ================================
# SCRIPT DE VALIDACIÓN DE SEGURIDAD
# URDIMBRE APPLICATION
# ================================

echo "🔐 VALIDADOR DE SEGURIDAD URDIMBRE"
echo "=================================="
echo ""

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Contadores
PASSED=0
FAILED=0
WARNINGS=0

# Función para imprimir resultados
print_success() {
    echo -e "${GREEN}✅ $1${NC}"
    ((PASSED++))
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
    ((FAILED++))
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
    ((WARNINGS++))
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

echo "🔍 Iniciando validación de seguridad..."
echo ""

# ================================
# VALIDAR ARCHIVO .ENV
# ================================
print_info "1. VALIDANDO ARCHIVO .env"

if [ ! -f ".env" ]; then
    print_error "Archivo .env no encontrado"
else
    print_success "Archivo .env encontrado"
    
    # Verificar que .env esté en .gitignore
    if grep -q "\.env" .gitignore 2>/dev/null; then
        print_success ".env está protegido en .gitignore"
    else
        print_error ".env NO está en .gitignore - ¡PELIGRO!"
    fi
    
    # Validar JWT_SECRET_KEY
    if grep -q "JWT_SECRET_KEY=" .env; then
        JWT_SECRET=$(grep "JWT_SECRET_KEY=" .env | cut -d'=' -f2)
        JWT_LENGTH=${#JWT_SECRET}
        
        if [ $JWT_LENGTH -ge 64 ]; then
            print_success "JWT_SECRET_KEY tiene longitud adecuada ($JWT_LENGTH caracteres)"
            
            # Verificar si es hexadecimal
            if [[ "$JWT_SECRET" =~ ^[0-9a-fA-F]+$ ]]; then
                print_success "JWT_SECRET_KEY es hexadecimal válido"
            else
                print_warning "JWT_SECRET_KEY no es hexadecimal puro"
            fi
            
            # Detectar Base64 (tu problema anterior)
            if [[ "$JWT_SECRET" =~ [+/=] ]]; then
                print_error "JWT_SECRET_KEY parece ser Base64 - usa hexadecimal: openssl rand -hex 64"
            fi
        else
            print_error "JWT_SECRET_KEY muy corto ($JWT_LENGTH chars). Mínimo: 64"
        fi
    else
        print_error "JWT_SECRET_KEY no configurado en .env"
    fi
    
    # Validar contraseñas
    if grep -q "DB_PASSWORD=$" .env; then
        print_error "DB_PASSWORD está vacío"
    elif grep -q "DB_PASSWORD=" .env; then
        print_success "DB_PASSWORD configurado"
    fi
    
    # Detectar contraseñas débiles
    if grep -E "(pass1234|password|123456|admin)" .env >/dev/null; then
        print_error "Contraseñas débiles detectadas en .env"
    else
        print_success "No se detectaron contraseñas débiles obvias"
    fi
fi

echo ""

# ================================
# VALIDAR ARCHIVOS JAVA
# ================================
print_info "2. VALIDANDO CÓDIGO JAVA"

# Buscar hardcodeo en archivos Java
HARDCODED_SECRETS=$(grep -r "password\|secret\|key" src/ --include="*.java" | grep -v "System.getenv\|@Value" | wc -l)

if [ $HARDCODED_SECRETS -eq 0 ]; then
    print_success "No se encontraron secrets hardcodeados en código Java"
else
    print_error "$HARDCODED_SECRETS posibles secrets hardcodeados encontrados"
fi

# Verificar uso de variables de entorno
ENV_USAGE=$(grep -r "@Value\|System.getenv" src/ --include="*.java" | wc -l)
if [ $ENV_USAGE -gt 0 ]; then
    print_success "Se detectó uso de variables de entorno ($ENV_USAGE referencias)"
else
    print_warning "No se detectó uso de variables de entorno"
fi

echo ""

# ================================
# VALIDAR APPLICATION.PROPERTIES
# ================================
print_info "3. VALIDANDO application.properties"

if [ -f "src/main/resources/application.properties" ]; then
    # Verificar que use variables de entorno
    if grep -E '\$\{[A-Z_]+\}' src/main/resources/application.properties >/dev/null; then
        print_success "application.properties usa variables de entorno"
    else
        print_warning "application.properties podría no usar variables de entorno"
    fi
    
    # Verificar que no tenga secrets hardcodeados
    if grep -E "(password|secret|key)=" src/main/resources/application.properties | grep -v '\$\{' >/dev/null; then
        print_error "Posibles secrets hardcodeados en application.properties"
    else
        print_success "No se detectaron secrets hardcodeados en application.properties"
    fi
else
    print_warning "application.properties no encontrado"
fi

echo ""

# ================================
# VALIDAR GITIGNORE
# ================================
print_info "4. VALIDANDO .gitignore"

if [ -f ".gitignore" ]; then
    PROTECTED_PATTERNS=(".env" "*.env" "application-secret.properties" "*.key" "*.pem")
    
    for pattern in "${PROTECTED_PATTERNS[@]}"; do
        if grep -q "$pattern" .gitignore; then
            print_success "Patrón '$pattern' protegido en .gitignore"
        else
            print_warning "Patrón '$pattern' NO está en .gitignore"
        fi
    done
else
    print_error ".gitignore no encontrado"
fi

echo ""

# ================================
# VERIFICAR PERMISOS DE ARCHIVOS
# ================================
print_info "5. VERIFICANDO PERMISOS DE ARCHIVOS"

if [ -f ".env" ]; then
    ENV_PERMS=$(stat -c "%a" .env 2>/dev/null || stat -f "%A" .env 2>/dev/null)
    if [ "$ENV_PERMS" = "600" ] || [ "$ENV_PERMS" = "644" ]; then
        print_success "Permisos de .env son seguros ($ENV_PERMS)"
    else
        print_warning "Permisos de .env podrían ser inseguros ($ENV_PERMS)"
    fi
fi

echo ""

# ================================
# GENERAR NUEVO JWT SECRET
# ================================
print_info "6. GENERADOR DE JWT SECRET SEGURO"

echo "🔐 Generando nuevo JWT secret hexadecimal..."
if command -v openssl >/dev/null 2>&1; then
    NEW_JWT_SECRET=$(openssl rand -hex 64)
    echo "✅ Nuevo JWT_SECRET_KEY (hexadecimal):"
    echo "$NEW_JWT_SECRET"
    echo ""
    echo "📋 Copia este valor a tu .env:"
    echo "JWT_SECRET_KEY=$NEW_JWT_SECRET"
elif command -v python3 >/dev/null 2>&1; then
    NEW_JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(64))")
    echo "✅ Nuevo JWT_SECRET_KEY (hexadecimal):"
    echo "$NEW_JWT_SECRET"
    echo ""
    echo "📋 Copia este valor a tu .env:"
    echo "JWT_SECRET_KEY=$NEW_JWT_SECRET"
else
    print_warning "No se puede generar JWT secret automáticamente"
    echo "Instala OpenSSL o Python3 y ejecuta:"
    echo "openssl rand -hex 64"
fi

echo ""

# ================================
# RESUMEN FINAL
# ================================
echo "📊 RESUMEN DE VALIDACIÓN"
echo "========================"
echo -e "${GREEN}✅ Validaciones pasadas: $PASSED${NC}"
echo -e "${YELLOW}⚠️  Advertencias: $WARNINGS${NC}"
echo -e "${RED}❌ Errores encontrados: $FAILED${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    if [ $WARNINGS -eq 0 ]; then
        echo -e "${GREEN}🎉 ¡CONFIGURACIÓN COMPLETAMENTE SEGURA!${NC}"
    else
        echo -e "${YELLOW}🔧 Configuración mayormente segura, revisa las advertencias${NC}"
    fi
else
    echo -e "${RED}🚨 ERRORES CRÍTICOS ENCONTRADOS - CORREGIR ANTES DE PRODUCCIÓN${NC}"
fi

echo ""
echo "🔐 Validación completada"