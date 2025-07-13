"use client"

import type { ChangeEvent } from "react"
import { Label } from "@/components/ui/label"
import { Input } from "@/components/ui/input"

interface FileUploadProps {
  label: string
  onChange: (file: File | null) => void
}

export function FileUpload({ label, onChange }: FileUploadProps) {
  const handleFileChange = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0] || null
    onChange(file)
  }

  return (
    <div className="grid w-full max-w-sm items-center gap-1.5">
      <Label htmlFor={label}>{label}:</Label>
      <Input id={label} type="file" accept="image/*" onChange={handleFileChange} className="cursor-pointer" />
    </div>
  )
}

