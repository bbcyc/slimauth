<?php

// To the first group of routes, I add:

 $this->get('/auth/activate', 'AuthController:getActivate')->setName('auth.activate');

 $this->get('/auth/password/recover', 'PasswordController:getRecoverPassword')->setName('auth.password.recover'); 
 $this->post('/auth/password/recover', 'PasswordController:postRecoverPassword'); 

 $this->get('/auth/password/reset', 'PasswordController:getResetPassword')->setName('auth.password.reset'); 
 $this->post('/auth/password/reset', 'PasswordController:postResetPassword');

// In AuthController.php:

    public function getActivate($request, $response)
    {
        $email = $request->getParam('email');
        $identifier = $request->getParam('identifier');

        $hashedIdentifier = $this->hash->hash($identifier);

        $user = $this->user->where('email', $email)
                           ->where('active', false)
                           ->first();


        if(!$user || !$this->hash->hashCheck($user->active_hash, $hashedIdentifier)) {

            $this->flash->addMessage('error', 'There was a problem activating your account.');
            return $response->withRedirect($this->router->pathFor('home'));
        } else {

            $user->activateAccount();
            $this->flash->addMessage('info', 'Your account have been activated and you can sign in.');
            return $response->withRedirect($this->router->pathFor('auth.signin'));
        }
    }

  //  In User model I add the function ActivateAccount:
    public function activateAccount()
    {
        $this->update([
            'active' => true,
            'active_hash' => null
        ]);
    }

// In PasswordController.php:

  public function getRecoverPassword($request, $response)
    {
        return $this->view->render($response, 'auth/password/recover.twig');
    }

    public function postRecoverPassword($request, $response)
    {
        $validation = $this->validator->validate($request, [
            'email' => your rules
        ]);

        if($validation->failed()) {
            return $response->withRedirect($this->router->pathFor('auth.password.recover'));
        }
        
        $user = $this->user->where('email', $request->getParam('email'))->first();
        
        if(!$user) {

            $this->flash->addMessage('error', 'Could not find that user..');
            return $response->withRedirect($this->router->pathFor('auth.password.recover'));
  } elseif (!$user->active) {

            $this->flash->addMessage('error', 'Inactive account.');
            return $response->withRedirect($this->router->pathFor('auth.password.recover'));

        } else {

            $identifier = $this->randomlib->generateString(128);

            $user->update([
                'recover_hash' => $this->hash->hash($identifier)
            ]);
        
            $this->mailer->send('email/auth/password/recover.php', ['user' => $user, 'identifier' => $identifier], function($message) use ($user) {
                $message->to($user->email);
                $message->subject('Recover your password.');
            });

            $this->flash->addMessage('info', 'We have emailed you instructions to reset your password.');
            
            return $response->withRedirect($this->router->pathFor('home'));
        }
    }

    public function getResetPassword($request, $response)
    {
        $email = $request->getParam('email');
        $identifier = $request->getParam('identifier');

        $hashedIdentifier = $this->hash->hash($identifier);

        $user = $this->user->where('email', $email)
                           ->first();

        if(!$user) {
            $this->flash->addMessage('error', 'Email unknown.');
            return $response->withRedirect($this->router->pathFor('home'));
        } 

        if (!$user->active) {
            $this->flash->addMessage('error', 'Inactive account.');
            return $response->withRedirect($this->router->pathFor('home'));
        }

        if(!$user->recover_hash) {
            $this->flash->addMessage('error', 'User has not ask reseting password.');
            return $response->withRedirect($this->router->pathFor('home'));
        }

        if(!$this->hash->hashCheck($user->recover_hash, $hashedIdentifier)) {
            $this->flash->addMessage('error', 'Hash unknown.');
            return $response->withRedirect($this->router->pathFor('home'));
        }
        
        return $this->view->render($response, 
                                   'auth/password/reset.twig', 
                                   ['email' => $user->email, 
                                    'identifier' => $identifier]
        );
    }

    public function postResetPassword($request, $response)
    {
        $email = $request->getParam('email');
        $identifier = $request->getParam('identifier');
        $hashedIdentifier = $this->hash->hash($identifier);

        $user = $this->user->where('email', $email)->first();
        
        if(!$user || !$user->active || !$user->recover_hash || !$this->hash->hashCheck($user->recover_hash, $hashedIdentifier)) {
            return $response->withRedirect($this->router->pathFor('home'));
        } 
        
        $validation = $this->validator->validate($request, [
            'password' => your rules,
            'password_confirm' => your rules,
        ]);
      
        if($validation->failed()) {
            return $this->view->render($response, 
                                'auth/password/reset.twig', 
                                ['email' => $user->email, 
                                 'identifier' => $identifier,
                                 'errors' => $validation->getErrors()    //Strange issue, If I remove this line the errors shows with a second click in reset button
                                 ]
            );
        }

        $user->update([
                        'password' => $this->hash->password($request->getParam('password')),
                        'recover_hash' => null
        ]);

        $this->flash->addMessage('info', 'Your password has been reset and you can now sign in.');

        return $response->withRedirect($this->router->pathFor('auth.signin'));
    }﻿

Class Hash:

class Hash
{
 protected $algo;
 protected $cost;

 public function __construct($algo, $cost)
 {
  $this->algo = $algo;
  $this->cost = $cost;
 }

 public function password($password) 
 {
  return password_hash(
   $password,
   $this->algo,
   ['cost' => $this->cost]
  );
 }

 public function passwordCheck($password, $hash)
 {
  return password_verify($password, $hash);
 }

 public function hash($input)
 {
  return hash('sha256', $input);
 }

 public function hashCheck($known, $user)
 {
  return hash_equals($known, $user);
 }
}﻿



