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
        Schema::create('surat_kontrols', function (Blueprint $table) {
            $table->id();
            $table->string('noSuratKontrol')->unique()->index();
            $table->string('noSepAsalKontrol');
            $table->date('tglRencanaKontrol');
            $table->string('namaDokter');
            $table->string('noKartu');
            $table->string('nama');
            $table->string('kelamin');
            $table->string('tglLahir');
            $table->string('namaDiagnosa')->nullable();;
            $table->string('kodeDokter');
            $table->string('poliTujuan');
            $table->string('noRujukan')->nullable();
            $table->string('jnsPelayanan')->nullable();
            $table->string('jnsKontrol')->nullable();
            $table->string('namaJnsKontrol')->nullable();
            $table->date('tglTerbitKontrol')->nullable();
            $table->string('poliAsal')->nullable();
            $table->string('namaPoliAsal')->nullable();
            $table->string('namaPoliTujuan')->nullable();
            $table->string('tglSEP')->nullable();
            $table->string('terbitSEP')->nullable();
            $table->string('user')->nullable();
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
        Schema::dropIfExists('surat_kontrols');
    }
};
