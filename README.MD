## 2021 CNU 정보보호 E2EEClient

##### 201602018 신희강

※ 해당 client는 정보보호 과제 수행을 위한 서버에서만 작동합니다.

### To do list

-   [x] GUI 구현
-   [x] 서버 Connect 구현
-   [x] 사용자 인증 (로그인) 구현
-   [x] Send 버튼 클릭시 공개키 교환 구현 (RSA 알고리즘)
-   [x] 공개키 교환 후 대칭키 교환 구현
-   [x] 대칭키 교환 후 메세지 전송 구현 (AES-256-CBC 알고리즘)
-   [x] 메세지 받아 화면에 보여주는 기능 구현
-   [x] 로그아웃 구현

### 사용한 암호화 라이브러리 (pycryptodome)

-   pycrypto는 python 버전 3.0부턴 사용불가.
-   pycrypto의 확장버전인 pycryptodome를 사용
-   [pycryptodome · PyPI](https://pypi.org/project/pycryptodome/)

### 기능 동작 순서

#### 발신자

1. Server, Port 정보를 입력 후, Connect 버튼을 눌러 소켓통신 서버에 접속
2. User란에 접속할 아이디를 입력하고 Login 버튼을 클릭하면 인증을 하는 Payload를 전송해 로그인
3. 로그인이 되면 Crypto라이브러리의 RSA 모듈을 사용해 자신의 공개키와 개인키를 생성
4. To에 메세지를 보낼 상대방의 아이디를 입력하고 GUI 하단의 입력란에 메세지를 입력 후, Send 버튼을 클릭
5. Send 버튼이 클릭되면 상대방의 공개키와 대칭키를 가지고 있는지 확인
6. 키가 없다면 Crpyto라이브러리의 Random 모듈을 통해 16바이트의 IV를 생성 후,
   자신의 공개키를 Base64로 인코딩하여 IV와 함께 Payload를 작성해 상대방에게 전송
7. 상대방의 공개키를 받을 때 까지 대기하다가 상대방의 공개키를 받으면 Crypto 라이브러리의 Random 모듈을 사용해 32바이트의 대칭키를 생성
8. 상대방의 공개키로 대칭키를 RSA 알고리즘을 통해 암호화 한 후, 상대방에게 전송과 동시에
   상대방들의 정보를 담고있는 딕셔너리에 해당 상대방의 이름을 키로 하여 상대방의 공개키, IV, 대칭키를 저장
9. 상대방이 대칭키 수신이 완료되면 대칭키와 IV로 메세지를 AES-256-CBC알고리즘으로 암호화 한 후, Base64 인코딩을 해 Payload에 담아 상대방에게 전송
10. 상대방이 메세지를 수신하면 자신의 채팅창에 자신이 보낸 메세지를 작성
11. 이 후 메시지 수신시, 상대방들 정보를 담고있는 딕셔너리에서 상대방의 키정보가 있는지 확인
12. 키 정보가 있으면 그 대칭키로 메세지를 암호화해 메세지 전송

#### 수신자

1. Server, Port 정보를 입력 후, Connect 버튼을 눌러 소켓통신 서버에 접속
2. User란에 접속할 아이디를 입력하고 Login 버튼을 클릭하면 인증을 하는 Payload를 전송해 로그인
3. 로그인이 되면 Crypto라이브러리의 RSA 모듈을 사용해 자신의 공개키와 개인키를 생성
4. 상대방으로부터 메세지를 수신받으면 키인지 메세지인지 확인
5. 키인 경우 상대방이 공개키를 전송한 것이므로 이를 딕셔너리에 저장하고 자신의 키를 상대방에게 전송 후 대칭키가 올 때까지 대기
6. 암호화된 대칭키를 받으면 자신의 개인키로 RSA 알고리즘 복호화를 실행해 상대방의 대칭키를 획득 후 딕셔너리에 저장
7. 이 후 메세지가 수신된다면 자신의 딕셔너리에서 상대방의 대칭키와 IV를 찾은 후, AES-256-CBC알고리즘으로 메세지를 복호화 해 자신의 채팅창에 메세지를 작성
