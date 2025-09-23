'use client'
import { NavBar } from '@/components/NavBar'
import PasswordStrengthChecker from '@/components/password-strength-checker'
import React from 'react'

function page() {
  return (
    <>
      <NavBar />
      <PasswordStrengthChecker />
    </>
  )
}

export default page