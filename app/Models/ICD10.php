<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class ICD10 extends Model
{
    use HasFactory;
    protected $connection = 'mysql2';
    protected $table = 'mt_icd10';
    public $timestamps = false;
}
