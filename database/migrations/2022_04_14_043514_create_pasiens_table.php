<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('pasiens', function (Blueprint $table) {
            $table->id();
            $table->string('norm')->unique();
            $table->string('nomorkartu')->unique()->nullable();
            $table->string('nik')->index()->unique();
            $table->string('nomorkk')->nullable();
            $table->string('nama')->nullable();;
            $table->string('jeniskelamin')->nullable();;
            $table->string('tanggallahir')->nullable();;
            $table->string('nohp')->nullable();;
            $table->string('alamat')->nullable();;
            $table->string('kodeprop')->nullable();;
            $table->string('namaprop')->nullable();
            $table->string('kodedati2')->nullable();
            $table->string('namadati2')->nullable();
            $table->string('kodekec')->nullable();
            $table->string('namakec')->nullable();
            $table->string('kodekel')->nullable();
            $table->string('namakel')->nullable();
            $table->string('rt')->nullable();
            $table->string('rw')->nullable();
            $table->string('status')->default(1);
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('pasiens');
    }
};
