const TOKEN_KEY = 'cerberus.apiToken'
let memoryToken = ''

export function getToken() {
  try {
    return sessionStorage.getItem(TOKEN_KEY) || memoryToken
  } catch {
    return memoryToken
  }
}

export function setToken(t: string) {
  memoryToken = t
  try {
    if (t) sessionStorage.setItem(TOKEN_KEY, t)
    else sessionStorage.removeItem(TOKEN_KEY)
  } catch {
    /* memory only */
  }
}
