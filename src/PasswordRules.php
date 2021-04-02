<?php

namespace luppakorva\LaravelNISTPasswordRules;

use luppakorva\LaravelNISTPasswordRules\Rules\BreachedPasswords;
use luppakorva\LaravelNISTPasswordRules\Rules\ContextSpecificWords;
use luppakorva\LaravelNISTPasswordRules\Rules\DerivativesOfContextSpecificWords;
use luppakorva\LaravelNISTPasswordRules\Rules\DictionaryWords;
use luppakorva\LaravelNISTPasswordRules\Rules\RepetitiveCharacters;
use luppakorva\LaravelNISTPasswordRules\Rules\SequentialCharacters;

abstract class PasswordRules
{
    public static function register($username, $requireConfirmation = true)
    {
        $rules = [
            'required',
            'string',
            'min:8',
        ];

        if ($requireConfirmation) {
            $rules[] = 'confirmed';
        }

        return array_merge($rules, [
            new SequentialCharacters(),
            new RepetitiveCharacters(),
            new DictionaryWords(),
            new ContextSpecificWords($username),
            new DerivativesOfContextSpecificWords($username),
            new BreachedPasswords(),
        ]);
    }

    public static function changePassword($username, $oldPassword = null)
    {
        $rules = self::register($username);

        if ($oldPassword) {
            $rules = array_merge($rules, [
                'different:'.$oldPassword,
            ]);
        }

        return $rules;
    }

    public static function optionallyChangePassword($username, $oldPassword = null)
    {
        $rules = self::changePassword($username, $oldPassword);

        $rules = array_merge($rules, [
            'nullable',
        ]);

        foreach ($rules as $key => $rule) {
            if (is_string($rule) && $rule === 'required') {
                unset($rules[$key]);
            }
        }

        return $rules;
    }

    public static function login()
    {
        return [
            'required',
            'string',
        ];
    }
}
