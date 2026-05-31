export async function login(email, password) {
  return { token: 'mock-jwt-token', userId: 'user-001', email };
}

export async function register(payload) {
  return { token: 'mock-jwt-token', userId: 'user-001', ...payload };
}
