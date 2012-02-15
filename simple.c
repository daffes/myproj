int a = 2;

void f() {
  printf("A\n");
  a = 3;
  printf("B\n");
}

int main() {
  f();
  return 0;
}
