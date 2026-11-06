import 'dart:convert';
import 'dart:core';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:flutter/foundation.dart';
import 'package:google_sign_in/google_sign_in.dart';
import 'package:http/http.dart' as http;

class AuthService {
  static const String baseUrl = 'https://signfix.me/api';

  // الـ Web Client ID الخاص بالسيرفر
  static const String _googleServerClientId =
      '887037934986-p0of85qk1e876s2aavl36eaqthk9i49q.apps.googleusercontent.com';

  /// تسجيل الدخول عبر Google ومزامنة الحساب مع Firebase وسيرفر SignFix
  static Future<Map<String, dynamic>?> signInWithGoogle({
    String role = 'customer',
  }) async {
    try {
      // 1. تهيئة Google Sign In بـ serverClientId لضمان الحصول على idToken
      final GoogleSignIn googleSignIn = GoogleSignIn(
        scopes: ['email', 'profile'],
        serverClientId: _googleServerClientId,
      );

      // تسجيل الخروج القديم لضمان إتاحة اختيار الحساب للمستخدم
      await googleSignIn.signOut();
      final GoogleSignInAccount? googleUser = await googleSignIn.signIn();

      if (googleUser == null) {
        return null; // إلغاء التسجيل بواسطة المستخدم
      }

      // 2. الحصول على تفاصيل المصادقة من Google
      final GoogleSignInAuthentication googleAuth =
          await googleUser.authentication;

      // 3. إنشاء اعتماد (Credential) لـ Firebase Auth
      final AuthCredential credential = GoogleAuthProvider.credential(
        accessToken: googleAuth.accessToken,
        idToken: googleAuth.idToken,
      );

      // 4. تسجيل الدخول في Firebase Auth
      final UserCredential userCredential =
          await FirebaseAuth.instance.signInWithCredential(credential);
      final User? firebaseUser = userCredential.user;

      if (firebaseUser == null) {
        throw Exception('فشل في تسجيل الدخول عبر Firebase Auth');
      }

      // 5. استخراج Firebase ID Token لإرساله إلى SignFix Backend
      final String? firebaseIdToken = await firebaseUser.getIdToken();
      if (firebaseIdToken == null || firebaseIdToken.isEmpty) {
        throw Exception('لم يتم التمكن من الحصول على Firebase ID Token');
      }

      // 6. إرسال الطلب إلى SignFix Backend API (/api/auth/google)
      final response = await http.post(
        Uri.parse('$baseUrl/auth/google'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'idToken': firebaseIdToken,
          'role': role,
        }),
      );

      final Map<String, dynamic> data = jsonDecode(response.body);

      // 7. التعامل مع النتيجة (200 لمستخدم موجود / 201 لمستخدم جديد)
      if (response.statusCode == 200 || response.statusCode == 201) {
        final String signFixToken = data['token']?.toString() ?? '';
        final Map<String, dynamic> user =
            (data['user'] as Map<String, dynamic>?) ?? {};
        final bool isNewUser = data['isNewUser'] == true;

        return {
          'token': signFixToken,
          'user': user,
          'isNewUser': isNewUser,
        };
      } else {
        final String errMsg = data['error']?.toString() ??
            'فشلت عملية المصادقة (${response.statusCode})';
        throw Exception(errMsg);
      }
    } catch (e) {
      debugPrint('❌ Google Sign-In Error: $e');
      rethrow;
    }
  }

  /// إرسال كود OTP للتحقق من رقم الهاتف
  static Future<void> requestPhoneOtp({
    required String phoneNumber,
    required void Function(String verificationId, int? resendToken) onCodeSent,
    required Future<void> Function(PhoneAuthCredential credential)
        onVerificationCompleted,
    required void Function(String error) onError,
    required void Function(String verificationId) onAutoRetrievalTimeout,
    int? forceResendingToken,
  }) {
    return FirebaseAuth.instance.verifyPhoneNumber(
      phoneNumber: phoneNumber,
      forceResendingToken: forceResendingToken,
      verificationCompleted: onVerificationCompleted,
      verificationFailed: (error) =>
          onError(error.message ?? 'فشل التحقق من رقم الهاتف.'),
      codeSent: onCodeSent,
      codeAutoRetrievalTimeout: onAutoRetrievalTimeout,
    );
  }

  /// الحصول على Firebase Token من بيانات الهاتف
  static Future<String> signInWithPhoneCredential(
      PhoneAuthCredential credential) async {
    final userCredential =
        await FirebaseAuth.instance.signInWithCredential(credential);
    final idToken = await userCredential.user?.getIdToken();
    if (idToken == null || idToken.isEmpty) {
      throw Exception('فشل الحصول على Firebase Token لرقم الهاتف.');
    }
    return idToken;
  }

  /// تسجيل الخروج الكامل
  static Future<void> signOut() async {
    await GoogleSignIn().signOut();
    await FirebaseAuth.instance.signOut();
  }
}
